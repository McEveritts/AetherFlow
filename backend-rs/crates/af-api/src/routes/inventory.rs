//! Production router wrapper that builds the real Axum `Router` while recording every
//! registered `(Method, path)` across nested and merged sub-routers.
//!
//! Because `routes::build_router()` and `routes::registered_production_routes()` both run
//! through the exact same `TrackedRouter` construction path, adding any route or HTTP method
//! anywhere in the production router tree automatically appears in the inventory and fails
//! `peers::scopes` coverage verification until explicitly classified.

use axum::extract::Request;
use axum::handler::Handler;
use axum::http::Method;
use axum::response::IntoResponse;
use axum::routing::{MethodRouter, Route};
use axum::Router;
use std::convert::Infallible;
use tower::{Layer, Service};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RegisteredRoute {
    pub(crate) method: Method,
    pub(crate) path: String,
}

pub(crate) struct TrackedMethodRouter<S = ()> {
    inner: MethodRouter<S>,
    methods: Vec<Method>,
}

impl<S> TrackedMethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn from_single(method: Method, inner: MethodRouter<S>) -> Self {
        Self {
            inner,
            methods: vec![method],
        }
    }

    pub(crate) fn get<H, T>(self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        let mut methods = self.methods;
        methods.push(Method::GET);
        Self {
            inner: self.inner.get(handler),
            methods,
        }
    }

    pub(crate) fn post<H, T>(self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        let mut methods = self.methods;
        methods.push(Method::POST);
        Self {
            inner: self.inner.post(handler),
            methods,
        }
    }

    pub(crate) fn put<H, T>(self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        let mut methods = self.methods;
        methods.push(Method::PUT);
        Self {
            inner: self.inner.put(handler),
            methods,
        }
    }

    pub(crate) fn patch<H, T>(self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        let mut methods = self.methods;
        methods.push(Method::PATCH);
        Self {
            inner: self.inner.patch(handler),
            methods,
        }
    }

    pub(crate) fn delete<H, T>(self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        let mut methods = self.methods;
        methods.push(Method::DELETE);
        Self {
            inner: self.inner.delete(handler),
            methods,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn head<H, T>(self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        let mut methods = self.methods;
        methods.push(Method::HEAD);
        Self {
            inner: self.inner.head(handler),
            methods,
        }
    }

    pub(crate) fn layer<L>(self, layer: L) -> Self
    where
        L: Layer<Route> + Clone + Send + 'static,
        L::Service: Service<Request> + Clone + Send + 'static,
        <L::Service as Service<Request>>::Response: IntoResponse + 'static,
        <L::Service as Service<Request>>::Error: Into<Infallible> + 'static,
        <L::Service as Service<Request>>::Future: Send + 'static,
    {
        Self {
            inner: self.inner.layer(layer),
            methods: self.methods,
        }
    }
}

pub(crate) fn get<H, T, S>(handler: H) -> TrackedMethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    TrackedMethodRouter::from_single(Method::GET, axum::routing::get(handler))
}

pub(crate) fn post<H, T, S>(handler: H) -> TrackedMethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    TrackedMethodRouter::from_single(Method::POST, axum::routing::post(handler))
}

pub(crate) fn put<H, T, S>(handler: H) -> TrackedMethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    TrackedMethodRouter::from_single(Method::PUT, axum::routing::put(handler))
}

#[allow(dead_code)]
pub(crate) fn patch<H, T, S>(handler: H) -> TrackedMethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    TrackedMethodRouter::from_single(Method::PATCH, axum::routing::patch(handler))
}

pub(crate) fn delete<H, T, S>(handler: H) -> TrackedMethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    TrackedMethodRouter::from_single(Method::DELETE, axum::routing::delete(handler))
}

pub(crate) fn head<H, T, S>(handler: H) -> TrackedMethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    TrackedMethodRouter::from_single(Method::HEAD, axum::routing::head(handler))
}

pub(crate) struct TrackedRouter<S = ()> {
    router: Router<S>,
    routes: Vec<RegisteredRoute>,
}

impl<S> TrackedRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    pub(crate) fn new() -> Self {
        Self {
            router: Router::new(),
            routes: Vec::new(),
        }
    }

    pub(crate) fn route(mut self, path: &str, method_router: TrackedMethodRouter<S>) -> Self {
        for method in method_router.methods {
            self.routes.push(RegisteredRoute {
                method,
                path: path.to_string(),
            });
        }
        self.router = self.router.route(path, method_router.inner);
        self
    }

    pub(crate) fn nest(mut self, prefix: &str, child: TrackedRouter<S>) -> Self {
        for entry in child.routes {
            self.routes.push(RegisteredRoute {
                method: entry.method,
                path: join_route_paths(prefix, &entry.path),
            });
        }
        self.router = self.router.nest(prefix, child.router);
        self
    }

    pub(crate) fn merge(mut self, other: TrackedRouter<S>) -> Self {
        self.routes.extend(other.routes);
        self.router = self.router.merge(other.router);
        self
    }

    pub(crate) fn fallback<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.router = self.router.fallback(handler);
        self
    }

    pub(crate) fn layer<L>(mut self, layer: L) -> Self
    where
        L: Layer<Route> + Clone + Send + 'static,
        L::Service: Service<Request> + Clone + Send + 'static,
        <L::Service as Service<Request>>::Response: IntoResponse + 'static,
        <L::Service as Service<Request>>::Error: Into<Infallible> + 'static,
        <L::Service as Service<Request>>::Future: Send + 'static,
    {
        self.router = self.router.layer(layer);
        self
    }

    pub(crate) fn with_state<S2>(self, state: S) -> TrackedRouter<S2> {
        TrackedRouter {
            router: self.router.with_state(state),
            routes: self.routes,
        }
    }

    pub(crate) fn into_router(self) -> Router<S> {
        self.router
    }

    #[cfg(test)]
    pub(crate) fn into_routes(self) -> Vec<RegisteredRoute> {
        self.routes
    }
}

pub(crate) fn join_route_paths(prefix: &str, child: &str) -> String {
    let trimmed_prefix = prefix.trim_end_matches('/');
    if child == "/" {
        return if trimmed_prefix.is_empty() {
            "/".to_string()
        } else {
            trimmed_prefix.to_string()
        };
    }
    let normalized_child = if child.starts_with('/') {
        child.to_string()
    } else {
        format!("/{child}")
    };
    if trimmed_prefix.is_empty() {
        normalized_child
    } else {
        format!("{trimmed_prefix}{normalized_child}")
    }
}
