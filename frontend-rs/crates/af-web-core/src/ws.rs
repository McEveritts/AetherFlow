use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize)]
struct WsTicketResponse {
    ticket: String,
}

#[derive(Deserialize)]
struct WsEnvelope {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    data: Value,
}

pub const HEARTBEAT_INTERVAL_MS: u64 = 30_000;
pub const PONG_TIMEOUT_MS: u64 = 10_000;
pub const POLL_INTERVAL_MS: u64 = 5_000;
pub const CONNECT_DEADLINE_MS: u64 = 8_000;
pub const MAX_FAILURES_BEFORE_POLLING: u32 = 3;
pub const MAX_FAILURES: u32 = MAX_FAILURES_BEFORE_POLLING;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConnectionState {
    #[default]
    Connecting,
    Connected,
    Reconnecting,
    Fallback,
    Offline,
}
impl ConnectionState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Connected => "API Connected",
            Self::Connecting => "Reconnecting",
            Self::Reconnecting => "Retrying",
            Self::Fallback => "Degraded Polling",
            Self::Offline => "Offline",
        }
    }
}
pub fn backoff_delay(attempt: u32, random: f64) -> u64 {
    let base = 1000.0 * 2f64.powi(attempt.min(30) as i32);
    let random = if random.is_finite() {
        random.clamp(0.0, 1.0)
    } else {
        0.5
    };
    (base * (0.8 + random * 0.4)).min(30_000.0).round() as u64
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportAction {
    Connect,
    Poll,
    SendPing,
    CloseZombie,
}
#[derive(Clone, Debug)]
pub struct ConnectionEngine {
    pub state: ConnectionState,
    pub failures: u32,
    pub disabled: bool,
    reconnect_at: u64,
    connect_deadline_at: u64,
    poll_at: u64,
    ping_at: u64,
    pong_deadline: Option<u64>,
}
impl ConnectionEngine {
    pub fn new(disabled: bool) -> Self {
        Self {
            state: if disabled {
                ConnectionState::Fallback
            } else {
                ConnectionState::Connecting
            },
            failures: 0,
            disabled,
            reconnect_at: 0,
            connect_deadline_at: u64::MAX,
            poll_at: 0,
            ping_at: 0,
            pong_deadline: None,
        }
    }
    pub fn connecting(&mut self, now: u64) {
        self.state = ConnectionState::Connecting;
        self.reconnect_at = u64::MAX;
        self.connect_deadline_at = now.saturating_add(CONNECT_DEADLINE_MS);
    }
    pub fn poll_connect_timeout(&mut self, now_ms: u64) -> bool {
        self.poll_connect_timeout_with_jitter(now_ms, 0.5)
    }
    fn poll_connect_timeout_with_jitter(&mut self, now_ms: u64, random: f64) -> bool {
        if self.state == ConnectionState::Connecting && now_ms >= self.connect_deadline_at {
            self.failed(now_ms, random);
            return true;
        }
        false
    }
    pub fn opened(&mut self, now: u64) {
        self.state = ConnectionState::Connected;
        self.connect_deadline_at = u64::MAX;
        self.failures = 0;
        self.ping_at = now + HEARTBEAT_INTERVAL_MS;
        self.pong_deadline = None;
    }
    pub fn received(&mut self) {
        self.pong_deadline = None;
    }
    pub fn failed(&mut self, now: u64, random: f64) {
        self.failures = self.failures.saturating_add(1);
        self.connect_deadline_at = u64::MAX;
        self.pong_deadline = None;
        self.state = if self.failures >= MAX_FAILURES || self.disabled {
            ConnectionState::Fallback
        } else {
            ConnectionState::Reconnecting
        };
        self.reconnect_at = now.saturating_add(if self.state == ConnectionState::Fallback {
            backoff_delay(self.failures.saturating_sub(1).max(5), random)
        } else {
            backoff_delay(self.failures - 1, random)
        });
        self.poll_at = now;
    }
    pub fn tick(&mut self, now: u64) -> Vec<TransportAction> {
        let mut actions = Vec::new();
        if self.state == ConnectionState::Offline {
            return actions;
        }
        if self.state == ConnectionState::Connected {
            if self.pong_deadline.is_some_and(|deadline| now >= deadline) {
                self.pong_deadline = None;
                actions.push(TransportAction::CloseZombie);
            } else if now >= self.ping_at {
                self.ping_at = now + HEARTBEAT_INTERVAL_MS;
                self.pong_deadline = Some(now + PONG_TIMEOUT_MS);
                actions.push(TransportAction::SendPing);
            }
        } else {
            if !self.disabled && now >= self.reconnect_at {
                self.connecting(now);
                actions.push(TransportAction::Connect);
            }
            if (self.state == ConnectionState::Fallback || self.failures >= MAX_FAILURES)
                && now >= self.poll_at
            {
                self.poll_at = now.saturating_add(POLL_INTERVAL_MS);
                actions.push(TransportAction::Poll);
            }
        }
        actions
    }
    pub fn stop(&mut self) {
        self.state = ConnectionState::Offline;
        self.connect_deadline_at = u64::MAX;
        self.pong_deadline = None;
    }
}

mod browser {
    use super::*;
    use crate::api::ApiClient;
    use futures::future::{AbortHandle, Abortable};
    use gloo_events::EventListener;
    use gloo_timers::callback::Interval;
    use std::{
        cell::{Cell, RefCell},
        rc::{Rc, Weak},
    };
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::spawn_local;
    #[derive(Clone, Debug)]
    pub enum TransportEvent {
        State(ConnectionState),
        Metrics(Value),
        Services(Value),
        Control(Value),
    }
    struct Inner {
        engine: RefCell<ConnectionEngine>,
        socket: RefCell<Option<web_sys::WebSocket>>,
        listeners: RefCell<Vec<EventListener>>,
        callback: Rc<dyn Fn(TransportEvent)>,
        connecting: Cell<bool>,
        polling: Cell<bool>,
        stopped: Cell<bool>,
        generation: Cell<u64>,
        ticket_abort: RefCell<Option<AbortHandle>>,
    }
    fn now() -> u64 {
        js_sys::Date::now() as u64
    }
    fn emit_state(inner: &Inner) {
        (inner.callback)(TransportEvent::State(inner.engine.borrow().state));
    }
    fn invalidate_attempt(inner: &Inner) {
        inner.connecting.set(false);
        inner.generation.set(inner.generation.get().wrapping_add(1));
        if let Some(abort) = inner.ticket_abort.borrow_mut().take() {
            abort.abort();
        }
        inner.listeners.borrow_mut().clear();
        if let Some(socket) = inner.socket.borrow_mut().take() {
            let _ = socket.close();
        }
    }
    fn expire_connect_attempt(inner: &Inner, generation: u64) {
        if inner.stopped.get() || inner.generation.get() != generation {
            return;
        }
        let expired = inner
            .engine
            .borrow_mut()
            .poll_connect_timeout_with_jitter(now(), js_sys::Math::random());
        if expired {
            invalidate_attempt(inner);
            emit_state(inner);
        }
    }
    fn arm_connect_deadline(inner: &Rc<Inner>, generation: u64) {
        inner.engine.borrow_mut().connecting(now());
        let weak = Rc::downgrade(inner);
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(CONNECT_DEADLINE_MS as u32).await;
            if let Some(inner) = weak.upgrade() {
                expire_connect_attempt(&inner, generation);
            }
        });
    }
    fn failed(inner: &Inner) {
        if inner.stopped.get() {
            return;
        }
        invalidate_attempt(inner);
        inner
            .engine
            .borrow_mut()
            .failed(now(), js_sys::Math::random());
        emit_state(inner);
    }
    fn poll(inner: Rc<Inner>) {
        if inner.polling.replace(true) || inner.stopped.get() {
            return;
        }
        let generation = inner.generation.get();
        spawn_local(async move {
            let (metrics, services) = futures::join!(
                ApiClient.get("/api/v1/auth/system/metrics"),
                ApiClient.get("/api/v1/auth/services")
            );
            if !inner.stopped.get()
                && inner.generation.get() == generation
                && inner.engine.borrow().state != ConnectionState::Connected
            {
                if let Ok(metrics) = metrics {
                    (inner.callback)(TransportEvent::Metrics(metrics));
                }
                if let Ok(services) = services {
                    (inner.callback)(TransportEvent::Services(services));
                }
            }
            inner.polling.set(false);
        });
    }
    fn connect(inner: Rc<Inner>) {
        if inner.stopped.get() || inner.connecting.replace(true) {
            return;
        }
        let generation = inner.generation.get().wrapping_add(1);
        inner.generation.set(generation);
        let (abort, registration) = AbortHandle::new_pair();
        *inner.ticket_abort.borrow_mut() = Some(abort);
        arm_connect_deadline(&inner, generation);
        spawn_local(async move {
            let result = Abortable::new(
                ApiClient.get_typed::<WsTicketResponse>("/api/v1/auth/ws/ticket"),
                registration,
            )
            .await;
            expire_connect_attempt(&inner, generation);
            if inner.stopped.get() || inner.generation.get() != generation {
                return;
            }
            inner.ticket_abort.borrow_mut().take();
            let ticket = result
                .ok()
                .and_then(Result::ok)
                .map(|response| response.ticket)
                .filter(|ticket| !ticket.is_empty());
            let Some(ticket) = ticket else {
                failed(&inner);
                return;
            };
            let Some(window) = web_sys::window() else {
                failed(&inner);
                return;
            };
            let protocol = if window.location().protocol().unwrap_or_default() == "https:" {
                "wss"
            } else {
                "ws"
            };
            let url = format!(
                "{protocol}://{}/api/v1/auth/ws?ticket={}",
                window.location().host().unwrap_or_default(),
                js_sys::encode_uri_component(&ticket)
            );
            let socket = match web_sys::WebSocket::new(&url) {
                Ok(socket) => socket,
                Err(_) => {
                    failed(&inner);
                    return;
                }
            };
            arm_connect_deadline(&inner, generation);
            inner.listeners.borrow_mut().clear();
            if let Some(old) = inner.socket.borrow_mut().take() {
                let _ = old.close();
            }
            let weak = Rc::downgrade(&inner);
            let open = EventListener::new(&socket, "open", move |_| {
                if let Some(inner) = weak
                    .upgrade()
                    .filter(|inner| !inner.stopped.get() && inner.generation.get() == generation)
                {
                    expire_connect_attempt(&inner, generation);
                    if inner.generation.get() != generation {
                        return;
                    }
                    inner.connecting.set(false);
                    inner.engine.borrow_mut().opened(now());
                    emit_state(&inner);
                }
            });
            let weak = Rc::downgrade(&inner);
            let close = EventListener::new(&socket, "close", move |_| {
                if let Some(inner) = weak
                    .upgrade()
                    .filter(|inner| inner.generation.get() == generation)
                {
                    failed(&inner);
                }
            });
            let weak = Rc::downgrade(&inner);
            let error = EventListener::new(&socket, "error", move |_| {
                if let Some(inner) = weak
                    .upgrade()
                    .filter(|inner| inner.generation.get() == generation)
                {
                    failed(&inner);
                }
            });
            let weak = Rc::downgrade(&inner);
            let message = EventListener::new(&socket, "message", move |event| {
                if let Some(inner) = weak
                    .upgrade()
                    .filter(|inner| !inner.stopped.get() && inner.generation.get() == generation)
                {
                    inner.engine.borrow_mut().received();
                    if let Some(text) = event
                        .dyn_ref::<web_sys::MessageEvent>()
                        .and_then(|e| e.data().as_string())
                    {
                        if let Ok(envelope) = serde_json::from_str::<WsEnvelope>(&text) {
                            match envelope.kind.as_str() {
                                "METRICS_UPDATE" => {
                                    let data = &envelope.data;
                                    let metrics = data.get("system").unwrap_or(data).clone();
                                    if let Some(services) = data.get("services") {
                                        (inner.callback)(TransportEvent::Services(
                                            services.clone(),
                                        ));
                                    }
                                    (inner.callback)(TransportEvent::Metrics(metrics));
                                }
                                "PONG" => {}
                                _ => {
                                    // Preserve extra control fields such as a top-level message.
                                    if let Ok(value) = serde_json::from_str::<Value>(&text) {
                                        (inner.callback)(TransportEvent::Control(value));
                                    }
                                }
                            }
                        }
                    }
                }
            });
            *inner.listeners.borrow_mut() = vec![open, close, error, message];
            *inner.socket.borrow_mut() = Some(socket);
        });
    }
    /// All generation, heartbeat, and pong-deadline state is instance-scoped on
    /// `Rc<Inner>`; separate connections never share transport lifecycle state.
    pub struct BrowserConnection {
        inner: Rc<Inner>,
        _timer: Interval,
    }
    impl BrowserConnection {
        pub fn start(callback: impl Fn(TransportEvent) + 'static) -> Self {
            let disabled = web_sys::window()
                .and_then(|w| js_sys::Reflect::get(&w, &"__AF_DISABLE_WS__".into()).ok())
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let inner = Rc::new(Inner {
                engine: RefCell::new(ConnectionEngine::new(disabled)),
                socket: RefCell::new(None),
                listeners: RefCell::new(vec![]),
                callback: Rc::new(callback),
                connecting: Cell::new(false),
                polling: Cell::new(false),
                stopped: Cell::new(false),
                generation: Cell::new(0),
                ticket_abort: RefCell::new(None),
            });
            emit_state(&inner);
            let tick = |inner: Rc<Inner>| {
                expire_connect_attempt(&inner, inner.generation.get());
                let actions = inner.engine.borrow_mut().tick(now());
                for action in actions {
                    match action {
                        TransportAction::Connect => connect(inner.clone()),
                        TransportAction::Poll => poll(inner.clone()),
                        TransportAction::SendPing => {
                            if let Some(socket) = inner.socket.borrow().as_ref() {
                                let _ = socket.send_with_str("{\"type\":\"PING\"}");
                            }
                        }
                        TransportAction::CloseZombie => {
                            failed(&inner);
                        }
                    }
                }
            };
            tick(inner.clone());
            let weak: Weak<Inner> = Rc::downgrade(&inner);
            let timer = Interval::new(250, move || {
                if let Some(inner) = weak.upgrade().filter(|i| !i.stopped.get()) {
                    tick(inner);
                }
            });
            Self {
                inner,
                _timer: timer,
            }
        }
        pub fn stop(&self) {
            self.inner.stopped.set(true);
            invalidate_attempt(&self.inner);
            self.inner.engine.borrow_mut().stop();
        }
    }
    impl Drop for BrowserConnection {
        fn drop(&mut self) {
            self.stop();
        }
    }
}
pub use browser::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn websocket_ticket_and_envelope_require_typed_fields_and_default_missing_data() {
        let ticket: WsTicketResponse =
            serde_json::from_str(r#"{"ticket":"one-use-ticket"}"#).unwrap();
        assert_eq!(ticket.ticket, "one-use-ticket");
        for invalid in [r#"{}"#, r#"{"ticket":null}"#, r#"{"ticket":123}"#] {
            assert!(serde_json::from_str::<WsTicketResponse>(invalid).is_err());
        }
        let metrics: WsEnvelope = serde_json::from_str(
            r#"{"type":"METRICS_UPDATE","data":{"system":{"cpu":12},"services":[]}}"#,
        )
        .unwrap();
        assert_eq!(metrics.kind, "METRICS_UPDATE");
        assert_eq!(
            metrics.data.get("system").unwrap().get("cpu"),
            Some(&Value::from(12))
        );
        let pong: WsEnvelope = serde_json::from_str(r#"{"type":"PONG"}"#).unwrap();
        assert_eq!(pong.kind, "PONG");
        assert!(pong.data.is_null());
        for invalid in [r#"{}"#, r#"{"type":null}"#, r#"{"type":123}"#] {
            assert!(serde_json::from_str::<WsEnvelope>(invalid).is_err());
        }
    }
    #[test]
    fn backoff_has_jitter_and_hard_cap() {
        assert_eq!(backoff_delay(0, 0.0), 800);
        assert_eq!(backoff_delay(0, 1.0), 1200);
        assert_eq!(backoff_delay(3, 0.5), 8000);
        assert_eq!(backoff_delay(100, 1.0), 30_000);
        assert_eq!(backoff_delay(0, f64::NAN), 1000);
    }
    #[test]
    fn stalled_attempts_have_deadlines_and_reach_fallback_polling() {
        let mut engine = ConnectionEngine::new(false);
        assert_eq!(engine.tick(0), vec![TransportAction::Connect]);
        let mut started_at = 0;
        for attempt in 1..=MAX_FAILURES_BEFORE_POLLING {
            let deadline = started_at + CONNECT_DEADLINE_MS;
            assert_eq!(engine.connect_deadline_at, deadline);
            assert!(!engine.poll_connect_timeout(deadline - 1));
            assert!(engine.tick(deadline - 1).is_empty());
            assert!(engine.poll_connect_timeout(deadline));
            assert_eq!(engine.failures, attempt);
            assert_eq!(engine.connect_deadline_at, u64::MAX);
            assert!(!engine.poll_connect_timeout(deadline));
            let retry_at = engine.reconnect_at;
            let delay = retry_at - deadline;
            assert!((800..=30_000).contains(&delay));
            if attempt < MAX_FAILURES_BEFORE_POLLING {
                assert_eq!(engine.state, ConnectionState::Reconnecting);
                assert!(
                    (backoff_delay(attempt - 1, 0.0)..=backoff_delay(attempt - 1, 1.0))
                        .contains(&delay)
                );
                assert!(engine.tick(retry_at - 1).is_empty());
                assert_eq!(engine.tick(retry_at), vec![TransportAction::Connect]);
                started_at = retry_at;
            } else {
                assert_eq!(engine.state, ConnectionState::Fallback);
                assert_eq!(engine.tick(deadline), vec![TransportAction::Poll]);
                assert!(engine.tick(deadline + POLL_INTERVAL_MS - 1).is_empty());
                assert_eq!(
                    engine.tick(deadline + POLL_INTERVAL_MS),
                    vec![TransportAction::Poll]
                );
            }
        }
    }
    #[test]
    fn fallback_keeps_polling_during_a_stalled_reconnect() {
        let mut engine = ConnectionEngine::new(false);
        for _ in 0..MAX_FAILURES_BEFORE_POLLING {
            engine.failed(0, 0.5);
        }
        let retry_at = engine.reconnect_at;
        assert_eq!(
            engine.tick(retry_at),
            vec![TransportAction::Connect, TransportAction::Poll]
        );
        assert_eq!(
            engine.tick(retry_at + POLL_INTERVAL_MS),
            vec![TransportAction::Poll]
        );
        assert!(engine.poll_connect_timeout(retry_at + CONNECT_DEADLINE_MS));
        assert_eq!(engine.state, ConnectionState::Fallback);
    }
    #[test]
    fn opening_or_stopping_cancels_the_connect_deadline() {
        let mut engine = ConnectionEngine::new(false);
        engine.connecting(0);
        engine.opened(1);
        assert_eq!(engine.connect_deadline_at, u64::MAX);
        assert!(!engine.poll_connect_timeout(CONNECT_DEADLINE_MS));
        assert_eq!(engine.failures, 0);
        engine.connecting(0);
        engine.stop();
        assert_eq!(engine.connect_deadline_at, u64::MAX);
        assert!(!engine.poll_connect_timeout(u64::MAX));
        assert!(engine.tick(u64::MAX).is_empty());
    }
    #[test]
    fn timeout_reconnect_jitter_and_timestamp_arithmetic_are_bounded() {
        let mut slow = ConnectionEngine::new(false);
        let mut fast = ConnectionEngine::new(false);
        for _ in 0..MAX_FAILURES_BEFORE_POLLING {
            slow.connecting(0);
            fast.connecting(0);
            assert!(slow.poll_connect_timeout_with_jitter(CONNECT_DEADLINE_MS, 1.0));
            assert!(fast.poll_connect_timeout_with_jitter(CONNECT_DEADLINE_MS, 0.0));
            assert!(fast.reconnect_at < slow.reconnect_at);
            assert!(slow.reconnect_at - CONNECT_DEADLINE_MS <= 30_000);
        }
        let mut engine = ConnectionEngine::new(false);
        engine.connecting(u64::MAX - 1);
        assert!(!engine.poll_connect_timeout(u64::MAX - 1));
        assert!(engine.poll_connect_timeout(u64::MAX));
        assert_eq!(engine.reconnect_at, u64::MAX);
    }
    #[test]
    fn heartbeat_ping_timeout_and_pong() {
        let mut e = ConnectionEngine::new(false);
        e.opened(0);
        assert!(e.tick(29999).is_empty());
        assert_eq!(e.tick(30000), vec![TransportAction::SendPing]);
        assert!(e.tick(39999).is_empty());
        assert_eq!(e.tick(40000), vec![TransportAction::CloseZombie]);
        e.opened(50000);
        e.tick(80000);
        e.received();
        assert!(e.tick(90000).is_empty());
    }
    #[test]
    fn three_failures_trigger_five_second_polling() {
        let mut e = ConnectionEngine::new(false);
        for i in 0..3 {
            e.failed(i * 1000, 0.5);
        }
        assert_eq!(e.state, ConnectionState::Fallback);
        assert_eq!(e.tick(2000), vec![TransportAction::Poll]);
        assert!(e.tick(6999).is_empty());
        assert_eq!(e.tick(7000), vec![TransportAction::Poll]);
    }
    #[test]
    fn disable_flag_never_connects() {
        let mut e = ConnectionEngine::new(true);
        assert_eq!(e.tick(0), vec![TransportAction::Poll]);
        assert_eq!(e.tick(30000), vec![TransportAction::Poll]);
    }
    #[test]
    fn open_resets_failures_and_stop_is_terminal() {
        let mut e = ConnectionEngine::new(false);
        e.failed(0, 0.5);
        assert_eq!(e.state, ConnectionState::Reconnecting);
        e.opened(1000);
        assert_eq!(e.failures, 0);
        e.stop();
        assert!(e.tick(u64::MAX - 1).is_empty());
    }
}
