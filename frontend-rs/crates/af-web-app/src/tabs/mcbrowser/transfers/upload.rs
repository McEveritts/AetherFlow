use super::*;

impl TransferQueue {
    pub(super) async fn head(self, job: &Rc<RefCell<UploadJob>>) -> Result<(u64, bool), ApiError> {
        let (session, size, fp, conflict) = {
            let job = job.borrow();
            (
                job.session.clone(),
                job.row.size,
                job.fingerprint.clone(),
                job.conflict.clone(),
            )
        };
        if !self.job_current(job) {
            return Err(error("Session ended"));
        }
        let response = checked(
            self.context,
            ApiClient
                .fetch_raw_body(&session, "HEAD", None, None, &[("Tus-Resumable", "1.0.0")])
                .await?,
        )
        .await?;
        if !self.job_current(job) {
            return Err(error("Session ended"));
        }
        let offset = header_u64(self.context, &response, "Upload-Offset")?;
        if header_u64(self.context, &response, "Upload-Length")? != size
            || offset > size
            || metadata_value(&response, "fingerprint").as_deref() != Some(fp.as_str())
            || metadata_value(&response, "conflict").as_deref() != Some(conflict.as_str())
        {
            return Err(error(
                "Upload identity or offset changed. Retain this session for inspection.",
            ));
        }
        let status = response.headers().get("Upload-Status").map_err(js_error)?;
        if !matches!(status.as_deref(), Some("uploading" | "completed")) {
            return Err(error("Server returned an invalid upload status"));
        }
        let completed = status.as_deref() == Some("completed");
        if completed && offset != size {
            return Err(error("Completed upload has an invalid offset"));
        }
        if let Some(path) = response.headers().get("Upload-Path").map_err(js_error)? {
            if let Ok(path) = relative_path(&path, false) {
                job.borrow_mut().row.path = path;
            }
        }
        Ok((offset, completed))
    }
    pub(super) async fn stop(
        self,
        job: &Rc<RefCell<UploadJob>>,
    ) -> Result<Option<TransferEnd>, ApiError> {
        if !self.job_current(job) {
            return Err(error("Session ended"));
        }
        let (cancel, pause, session) = {
            let job = job.borrow();
            (job.cancel, job.pause, job.session.clone())
        };
        if cancel {
            if session.is_empty() {
                return Ok(Some(TransferEnd::Cancelled));
            }
            if self.head(job).await?.1 {
                return Ok(Some(TransferEnd::Completed));
            }
            checked(
                self.context,
                ApiClient
                    .fetch_raw_body(
                        &session,
                        "DELETE",
                        None,
                        None,
                        &[("Tus-Resumable", "1.0.0")],
                    )
                    .await?,
            )
            .await?;
            return Ok(Some(TransferEnd::Cancelled));
        }
        Ok(pause.then_some(TransferEnd::Paused))
    }
    pub(super) async fn run(self, id: u64) -> Result<TransferEnd, ApiError> {
        let job = self
            .job(id)
            .ok_or_else(|| error("Transfer no longer exists"))?;
        if let Some(end) = self.stop(&job).await? {
            return Ok(end);
        }
        let (file, path, size, conflict) = {
            let job = job.borrow();
            (
                job.file.clone(),
                job.row.path.clone(),
                job.row.size,
                job.conflict.clone(),
            )
        };
        let start = js_sys::Date::now();
        if size <= DIRECT_BYTES {
            job.borrow_mut().row.status = TransferStatus::Uploading;
            self.publish();
            let body: JsValue = file.into();
            let signal = self.request_signal(&job)?;
            let result = ApiClient
                .fetch_raw_body_with_signal(
                    &format!("{BASE}/upload?path={}", encode(&path)),
                    "PUT",
                    Some(&body),
                    Some("application/octet-stream"),
                    &[],
                    Some(&signal),
                )
                .await;
            let result = match result {
                Ok(response) => response_value(self.context, response).await,
                Err(failure) => Err(failure),
            };
            job.borrow_mut().abort.take();
            if !self.job_current(&job) {
                return Err(error("Session ended"));
            }
            if result.is_err() {
                if let Some(end) = self.stop(&job).await? {
                    return Ok(end);
                }
            }
            let (data, _) = result?;
            if data["accounting_pending"] == true {
                self.context.toast(
                    tt(self.context, "Upload saved; storage accounting is pending."),
                    false,
                );
            }
            job.borrow_mut().row.rate =
                size as f64 / ((js_sys::Date::now() - start) / 1000.0).max(0.001);
            return Ok(TransferEnd::Completed);
        }
        if job.borrow().fingerprint.is_empty() {
            let fp = fingerprint(&file, size, &conflict).await?;
            job.borrow_mut().fingerprint = fp;
        }
        if let Some(end) = self.stop(&job).await? {
            return Ok(end);
        }
        if job.borrow().session.is_empty() {
            let fp = job.borrow().fingerprint.clone();
            let sessions = ApiClient
                .get(&format!(
                    "{BASE}/uploads?path={}&length={size}&fingerprint={}",
                    encode(&path),
                    encode(&fp)
                ))
                .await?;
            let uploads = crate::tabs::contracts::rows::<crate::tabs::contracts::TusUploadLookup>(
                &sessions["uploads"],
            );
            if let Some(existing) = uploads.iter().find(|row| {
                row.path == path
                    && row.length == Some(size)
                    && row.fingerprint == fp
                    && row.exists != Some(false)
                    && !row.upload_id.is_empty()
                    && matches!(
                        row.status.as_str(),
                        "uploading" | "completed" | "publishing"
                    )
            }) {
                let session = upload_location(&format!("{BASE}/uploads/{}", existing.upload_id))?;
                job.borrow_mut().session = session;
            } else {
                if !self.job_current(&job) {
                    return Err(error("Session ended"));
                }
                let metadata = format!(
                    "path {},fingerprint {},conflict {}",
                    base64(path.as_bytes()),
                    base64(fp.as_bytes()),
                    base64(conflict.as_bytes())
                );
                let length = size.to_string();
                let response = checked(
                    self.context,
                    ApiClient
                        .fetch_raw_body(
                            &format!("{BASE}/uploads"),
                            "POST",
                            None,
                            None,
                            &[
                                ("Tus-Resumable", "1.0.0"),
                                ("Upload-Length", &length),
                                ("Upload-Metadata", &metadata),
                                ("X-Upload-Conflict", &conflict),
                            ],
                        )
                        .await?,
                )
                .await?;
                let location = response.headers().get("Location").map_err(js_error)?
                    .ok_or_else(|| error("Upload creation returned no session URL; reselect to discover its state"))?;
                job.borrow_mut().session = upload_location(&location)?;
            }
        }
        let (mut offset, completed) = self.head(&job).await?;
        if completed {
            return Ok(TransferEnd::Completed);
        }
        let baseline = offset;
        let mut retries = 0;
        job.borrow_mut().row.status = TransferStatus::Uploading;
        while offset < size {
            job.borrow_mut().row.sent = offset;
            self.publish();
            if let Some(end) = self.stop(&job).await? {
                return Ok(end);
            }
            let end = (offset + CHUNK_BYTES).min(size);
            let slice = file
                .slice_with_f64_and_f64(offset as f64, end as f64)
                .map_err(js_error)?;
            let digest = worker_pool().sha256_blob(&slice).await.map_err(error)?;
            let digest_bytes = (0..digest.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&digest[index..index + 2], 16))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| error("Invalid worker checksum"))?;
            let checksum = format!("sha256 {}", base64(&digest_bytes));
            let body: &JsValue = slice.as_ref();
            let session = job.borrow().session.clone();
            let offset_header = offset.to_string();
            if let Some(end) = self.stop(&job).await? {
                return Ok(end);
            }
            let signal = self.request_signal(&job)?;
            let result = ApiClient
                .fetch_raw_body_with_signal(
                    &session,
                    "PATCH",
                    Some(body),
                    Some("application/offset+octet-stream"),
                    &[
                        ("Tus-Resumable", "1.0.0"),
                        ("Upload-Offset", &offset_header),
                        ("Upload-Checksum", &checksum),
                    ],
                    Some(&signal),
                )
                .await;
            let result = match result {
                Ok(response) if response.ok() => {
                    // PATCH success is metadata-only; release its unread body
                    // before a pause/cancel reconciliation can await another HEAD.
                    Ok(header_u64(self.context, &response, "Upload-Offset"))
                }
                Ok(response) => Err(response_value(self.context, response)
                    .await
                    .err()
                    .unwrap_or_else(|| error("Upload failed"))),
                Err(failure) => Err(failure),
            };
            job.borrow_mut().abort.take();
            if !self.job_current(&job) {
                return Err(error("Session ended"));
            }
            if let Some(end) = self.stop(&job).await? {
                return Ok(end);
            }
            let previous = offset;
            match result {
                Ok(received) => {
                    let received = received?;
                    if received != end {
                        return Err(error(
                            "Server acknowledged an unexpected chunk offset. Resume to reconcile.",
                        ));
                    }
                    offset = received;
                    retries = 0;
                }
                Err(failure) => {
                    if failure.status != 0
                        && failure.status < 500
                        && !matches!(failure.status, 408 | 409 | 429)
                    {
                        return Err(failure);
                    }
                    let (received, done) = self.head(&job).await?;
                    if received < previous || received > end {
                        return Err(error("Server offset moved outside the current chunk. Publication state is uncertain."));
                    }
                    if done {
                        return Ok(TransferEnd::Completed);
                    }
                    offset = received;
                    retries += 1;
                    if retries > 3 {
                        return Err(error(tt_with(
                            self.context,
                            "Transfer interrupted: {failure}. Resume to check the server.",
                            &[("failure", &tt(self.context, &failure.to_string()))],
                        )));
                    }
                    if offset == previous {
                        gloo_timers::future::TimeoutFuture::new(200 * (1 << (retries - 1))).await;
                    }
                }
            }
            {
                let mut job = job.borrow_mut();
                job.row.sent = offset;
                job.row.rate = (offset - baseline) as f64
                    / ((js_sys::Date::now() - start) / 1000.0).max(0.001);
            }
            self.publish();
        }
        // Reaching Upload-Length is not proof of publication. HEAD performs the
        // backend's publication reconciliation and must explicitly say completed.
        if self.head(&job).await?.1 {
            Ok(TransferEnd::Completed)
        } else {
            Err(error("All bytes reached staging; publication is unconfirmed. Resume to check the server."))
        }
    }
}
