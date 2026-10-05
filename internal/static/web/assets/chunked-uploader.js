/**
 * ChunkedUploader - Handles chunked/resumable file uploads for large files
 *
 * Features:
 * - Automatic chunking based on server config
 * - Retry logic with exponential backoff
 * - Parallel chunk uploads (configurable concurrency)
 * - Pause/resume capability
 * - localStorage persistence for resume after page refresh
 * - Progress tracking with ETA calculation
 * - Event-based architecture for UI updates
 *
 * @example
 * const uploader = new ChunkedUploader(file, {
 *   expiresInHours: 24,
 *   maxDownloads: 5,
 *   password: 'optional'
 * });
 *
 * uploader.on('progress', (progress) => {
 *   console.log(`${progress.percentage}% complete`);
 * });
 *
 * await uploader.init();
 * await uploader.uploadAllChunks();
 * const result = await uploader.complete();
 */
class ChunkedUploader {
    constructor(file, options = {}) {
        this.file = file;
        this.options = {
            expiresInHours: options.expiresInHours || 24,
            maxDownloads: options.maxDownloads || 0,
            password: options.password || '',
            clientEncrypted: !!options.clientEncrypted,
            // false (Ghost mode): never write resume state (it holds the filename) to localStorage
            persistState: options.persistState !== false,
            concurrency: options.concurrency || 10, // Increased from 6 to 10 for HTTP/2
            // 6 attempts with jittered 1s→30s backoff ride out ~30-60s of
            // network trouble (Wi-Fi handoff, brief outage) per chunk.
            retryAttempts: options.retryAttempts || 6,
            retryDelay: options.retryDelay || 1000, // Initial retry delay in ms
            maxRetryDelay: options.maxRetryDelay || 30000,
        };

        // Upload state
        this.uploadId = null;
        this.chunkSize = null;
        this.totalChunks = 0;
        this.uploadedChunks = new Set();
        this.isPaused = false;
        this.isCompleted = false;
        this.isCompleting = false;
        this.completionPromise = null;

        // Progress tracking
        this.startTime = null;
        this.uploadedBytes = 0;

        // Event listeners
        this.eventListeners = {};

        // Storage key for resume capability
        this.storageKey = null;

        // Aborts in-flight init/chunk/complete/status fetches on pause() or
        // abort(). Recreated by uploadAllChunks() so resume() gets a fresh
        // signal.
        this.abortController = new AbortController();

        // Network metrics for adaptive concurrency
        this.networkMetrics = {
            consecutiveSuccesses: 0,
            consecutiveFailures: 0,
            recentLatencies: [],      // Keep last 10 latencies
            avgLatency: 0,
            baselineLatency: null,    // Median of first 3 chunk latencies (Guard 2 anchor)
            minConcurrency: 2,
            maxConcurrency: 20,
            adjustmentThreshold: 5,   // Adjust after 5 consecutive successes/failures
            latencyThreshold: 8000,   // Initial value, recalculated in init() based on chunk size
            staticLatencyThreshold: 8000, // Chunk-size-based floor for the recalibrated threshold
            latencyDegradationLimit: 0.5  // Don't increase if latency >50% worse than baseline
        };

        // Progress throttling for better UI performance
        this.progressThrottle = {
            lastEmit: 0,
            minInterval: 250,         // Minimum 250ms between progress events
            chunksSinceLastEmit: 0,
            chunkThreshold: 5         // Or emit every 5 chunks, whichever comes first
        };

        // Detect if HTTP/2 is available for optimal concurrency
        this._detectHTTP2Support();
    }

    /**
     * Register event listener
     * @param {string} event - Event name (progress, error, complete, chunk_uploaded)
     * @param {function} callback - Callback function
     */
    on(event, callback) {
        if (!this.eventListeners[event]) {
            this.eventListeners[event] = [];
        }
        this.eventListeners[event].push(callback);
    }

    /**
     * Emit event to all registered listeners
     * @param {string} event - Event name
     * @param {*} data - Event data
     */
    emit(event, data) {
        if (this.eventListeners[event]) {
            this.eventListeners[event].forEach(callback => callback(data));
        }
    }

    /**
     * Detect HTTP/2 or HTTP/3 support and adjust concurrency
     * HTTP/2 and HTTP/3 allow higher concurrency without connection limits
     */
    _detectHTTP2Support() {
        // Check Performance API for HTTP/2 or HTTP/3
        if (window.performance && window.performance.getEntriesByType) {
            const navEntry = performance.getEntriesByType('navigation')[0];
            if (navEntry && navEntry.nextHopProtocol) {
                const protocol = navEntry.nextHopProtocol;
                // HTTP/2 (h2, h2c) or HTTP/3 (h3, h3-29, h3-*) support multiplexing
                if (protocol === 'h2' || protocol === 'h2c' || protocol === 'h3' || protocol.startsWith('h3-')) {
                    // HTTP/2 or HTTP/3 detected - can safely use higher concurrency
                    if (this.options.concurrency <= 10) {
                        this.options.concurrency = 12;
                    }
                    console.log(`${protocol.toUpperCase()} detected, using concurrency:`, this.options.concurrency);
                } else {
                    // HTTP/1.1 - use conservative concurrency
                    if (this.options.concurrency > 6) {
                        this.options.concurrency = 6;
                        console.log('HTTP/1.1 detected, limiting concurrency to 6');
                    }
                }
            }
        }
    }

    /**
     * Initialize chunked upload session
     * @returns {Promise<void>}
     */
    async init() {
        try {
            const response = await fetch('/api/upload/init', {
                method: 'POST',
                signal: this.abortController.signal,
                headers: Object.assign({
                    'Content-Type': 'application/json'
                }, this.options.clientEncrypted ? { 'X-SafeShare-Client-Encrypted': 'true' } : {}),
                body: JSON.stringify({
                    filename: this.file.name,
                    total_size: this.file.size,
                    chunk_size: this.chunkSize || 5242880, // Will be overridden by server
                    expires_in_hours: this.options.expiresInHours,
                    max_downloads: this.options.maxDownloads,
                    password: this.options.password,
                    client_encrypted: this.options.clientEncrypted
                })
            });

            if (!response.ok) {
                const error = await this.parseErrorResponse(response);
                throw error;
            }

            const data = await response.json();
            this.uploadId = data.upload_id;
            this.chunkSize = data.chunk_size;
            this.totalChunks = data.total_chunks;
            this.startTime = Date.now();

            // Calculate adaptive latency threshold based on actual chunk size
            // Formula: (chunkSize / 1.25MB/s) * 2x overhead
            // Assumes minimum 10 Mbps connection (1.25 MB/s) with 2x safety margin
            const chunkSizeMB = this.chunkSize / (1024 * 1024);
            this.networkMetrics.staticLatencyThreshold = Math.round((chunkSizeMB / 1.25) * 1000 * 2);
            this.networkMetrics.latencyThreshold = this.networkMetrics.staticLatencyThreshold;

            console.log(`Adaptive latency threshold: ${this.networkMetrics.latencyThreshold}ms for ${chunkSizeMB.toFixed(1)}MB chunks (${(this.networkMetrics.latencyThreshold / 1000).toFixed(1)}s)`);

            // Set storage key for resume capability
            this.storageKey = `chunked_upload_${this.uploadId}`;

            // Save initial state to localStorage
            this.saveState();

            this.emit('init', {
                uploadId: this.uploadId,
                totalChunks: this.totalChunks,
                chunkSize: this.chunkSize
            });

        } catch (error) {
            if (this._isCancellation(error)) {
                throw this._cancellationError();
            }
            throw this._reportError(error, { stage: 'init', error: error.message, code: error.code || null });
        }
    }

    /**
     * Upload a single chunk with retry logic
     * @param {number} chunkNumber - Chunk number (0-based)
     * @returns {Promise<void>}
     */
    async uploadChunk(chunkNumber) {
        let attempt = 0;
        const maxAttempts = this.options.retryAttempts;

        while (attempt < maxAttempts) {
            try {
                // Check if paused
                if (this.isPaused) {
                    throw this._cancellationError();
                }

                // Calculate chunk boundaries
                const start = chunkNumber * this.chunkSize;
                const end = Math.min(start + this.chunkSize, this.file.size);
                const chunkBlob = this.file.slice(start, end);

                // Calculate client-side SHA256 checksum
                const clientChecksum = await this._calculateChecksum(chunkBlob);

                // Create form data
                const formData = new FormData();
                formData.append('chunk', chunkBlob, `chunk_${chunkNumber}`);

                // Track upload latency for adaptive concurrency
                const uploadStartTime = Date.now();

                // Upload chunk (HTTP/2 handles connection reuse automatically)
                const response = await fetch(`/api/upload/chunk/${this.uploadId}/${chunkNumber}`, {
                    method: 'POST',
                    body: formData,
                    signal: this.abortController ? this.abortController.signal : undefined
                });

                if (!response.ok) {
                    const error = await this.parseErrorResponse(response);
                    throw error;
                }

                const data = await response.json();

                // Calculate upload latency
                const uploadLatency = Date.now() - uploadStartTime;

                // Verify checksum matches server (only if client-side checksum was calculated)
                if (clientChecksum && data.checksum && data.checksum !== clientChecksum) {
                    throw new Error(`Checksum mismatch for chunk ${chunkNumber}: client=${clientChecksum.substring(0, 8)}... server=${data.checksum.substring(0, 8)}...`);
                }

                // Track success for adaptive concurrency
                this._trackUploadSuccess(uploadLatency);

                // Mark chunk as uploaded
                this.uploadedChunks.add(chunkNumber);
                this.uploadedBytes += (end - start);

                // Save state
                this.saveState();

                // Emit progress event
                this.emitProgress();

                this.emit('chunk_uploaded', {
                    chunkNumber,
                    chunksUploaded: this.uploadedChunks.size,
                    totalChunks: this.totalChunks,
                    checksum: data.checksum
                });

                return; // Success

            } catch (error) {
                // Cancellation is not a failure: don't count it against the
                // network metrics, don't retry, don't emit 'error'.
                if (this._isCancellation(error)) {
                    throw error;
                }

                attempt++;

                // Track failure for adaptive concurrency (before retrying)
                if (attempt === 1) {  // Only track on first failure to avoid double-counting
                    this._trackUploadFailure();
                }

                // Client errors (bad request, upload gone/expired, too large)
                // won't succeed on retry; neither will a rate limit that
                // lasts longer than we're willing to wait.
                if (error.retryRecommended === false || this._retryAfterTooLong(error)) {
                    throw this._reportError(
                        new Error(`Chunk ${chunkNumber} upload failed (non-retryable error: ${error.code}): ${error.message}`),
                        { stage: 'chunk_upload', chunkNumber, error: error.message, code: error.code, retryRecommended: false }
                    );
                }

                if (attempt >= maxAttempts) {
                    throw this._reportError(
                        new Error(`Failed to upload chunk ${chunkNumber} after ${maxAttempts} attempts: ${error.message}`),
                        { stage: 'chunk_upload', chunkNumber, error: error.message, code: error.code, attempts: attempt }
                    );
                }

                const delay = this._retryDelay(attempt, error.retryAfter);
                console.warn(`Chunk ${chunkNumber} upload failed (attempt ${attempt}/${maxAttempts}, code: ${error.code || 'UNKNOWN'}), retrying in ${delay}ms...`);
                await this._waitForOnline();
                await this.sleep(delay);
            }
        }
    }

    /**
     * Upload all chunks with a sliding-window worker pool.
     *
     * Keeps `options.concurrency` chunks in flight at all times instead of
     * uploading fixed batches (where the slowest chunk stalls the whole batch).
     * Workers re-read `options.concurrency` between chunks, so adaptive
     * concurrency adjustments take effect mid-upload: the pool shrinks by
     * letting excess workers exit and grows by spawning new ones.
     *
     * @returns {Promise<void>}
     */
    async uploadAllChunks() {
        const pending = [];
        for (let i = 0; i < this.totalChunks; i++) {
            // Skip already uploaded chunks (for resume)
            if (!this.uploadedChunks.has(i)) {
                pending.push(i);
            }
        }

        // Fresh controller per (re)start so a resume() after pause() isn't
        // stuck with an already-aborted signal. Before the early return so
        // complete()/pollStatus() stay cancellable when nothing is pending.
        this.abortController = new AbortController();

        if (pending.length === 0) {
            return;
        }

        let nextIndex = 0;
        let activeWorkers = 0;
        let firstError = null;

        await new Promise((resolve, reject) => {
            const settle = () => {
                if (activeWorkers > 0) return;
                if (firstError) {
                    reject(firstError);
                } else if (this.isPaused && this.uploadedChunks.size < this.totalChunks) {
                    // Compare uploaded (not dispatched) chunks: in-flight
                    // chunks aborted by pause() were dispatched but never
                    // finished, and resolving here would let complete() run
                    // against missing chunks. pause()/abort() emit their own
                    // events, so no 'paused' emit here.
                    reject(this._cancellationError());
                } else {
                    resolve();
                }
            };

            const spawnWorkers = () => {
                while (activeWorkers < this.options.concurrency &&
                       nextIndex < pending.length &&
                       !firstError && !this.isPaused) {
                    worker();
                }
            };

            const worker = async () => {
                // Runs synchronously until the first await, so the counter is
                // accurate inside spawnWorkers' loop.
                activeWorkers++;
                try {
                    while (!firstError && !this.isPaused) {
                        // Shrink pool if adaptive concurrency was lowered
                        if (activeWorkers > this.options.concurrency) break;
                        if (nextIndex >= pending.length) break;
                        const chunkNumber = pending[nextIndex++];
                        await this.uploadChunk(chunkNumber);
                        // Grow pool if adaptive concurrency was raised
                        spawnWorkers();
                    }
                } catch (error) {
                    // Cancellation isn't a real error — settle() rejects with
                    // a single normalized 'Upload cancelled' instead.
                    if (!firstError && !this._isCancellation(error)) {
                        firstError = error;
                    }
                } finally {
                    activeWorkers--;
                    settle();
                }
            };

            spawnWorkers();
            // If pause was requested before any worker started, no worker
            // will ever call settle() — resolve/reject here instead of
            // leaving the promise pending forever.
            settle();
        });
    }

    /**
     * Complete the upload and assemble chunks
     * @returns {Promise<Object>} - Returns claim code and download URL
     */
    async complete() {
        // Prevent duplicate completion requests (race condition protection)
        if (this.isCompleting) {
            console.warn('Complete already in progress, ignoring duplicate call');
            return this.completionPromise;
        }

        this.isCompleting = true;

        try {
            // Store promise for duplicate calls to wait on
            this.completionPromise = (async () => {
                const response = await this._postComplete();
                const data = await response.json();

                // Check if response is HTTP 202 (Accepted) or has status "processing"
                // This means file assembly is happening asynchronously
                if (response.status === 202 || data.status === 'processing') {
                    // Emit assembling event to notify UI
                    this.emit('assembling', {
                        uploadId: this.uploadId,
                        message: data.message || 'File is being assembled...'
                    });

                    // Start polling for completion
                    const result = await this.pollStatus();

                    this.isCompleted = true;

                    // Clear saved state from localStorage
                    this.clearState();

                    this.emit('complete', result);

                    return result;
                }

                // If not 202, handle as synchronous completion (backward compatibility)
                this.isCompleted = true;

                // Clear saved state from localStorage
                this.clearState();

                this.emit('complete', data);

                return data;
            })();

            return await this.completionPromise;

        } catch (error) {
            if (this._isCancellation(error)) {
                // Normalize so callers filtering on 'Upload cancelled' don't
                // surface an AbortError message as a failure.
                throw this._cancellationError();
            }
            throw this._reportError(error, { stage: 'complete', error: error.message, code: error.code || null });
        } finally {
            this.isCompleting = false;
        }
    }

    /**
     * Check upload status. Does not emit 'error': a failed status check is
     * usually a transient blip that pollStatus() retries, and emitting here made
     * the page reset mid-assembly (dropping the E2E key from the share link).
     * Callers emit 'error' once they decide the failure is final.
     * @returns {Promise<Object>} - Upload status
     */
    async getStatus() {
        const response = await fetch(`/api/upload/status/${this.uploadId}`, {
            signal: this.abortController ? this.abortController.signal : undefined
        });

        if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            const error = new Error(body.error || 'Failed to get status');
            error.status = response.status;
            const retryAfter = parseInt(response.headers.get('Retry-After'), 10);
            if (Number.isFinite(retryAfter)) {
                error.retryAfterSeconds = retryAfter;
            }
            throw error;
        }

        return await response.json();
    }

    /**
     * Poll status endpoint until file assembly is complete
     * @param {number} pollInterval - Polling interval in milliseconds (default: 2000ms / 2 seconds)
     * @param {number} maxAttempts - Maximum number of polling attempts. Defaults
     *   to a budget scaled by file size (floor 150 = 5 minutes, plus one 2s
     *   attempt per 5MB), because assembly time grows with file size: a 20GB
     *   assembly on a slow disk (sequential read + hash + encryption + optional
     *   AV scan) can legitimately exceed a flat 5-minute cap even though the
     *   server is healthy and will finish.
     * @returns {Promise<Object>} - Final upload result with claim_code and download_url
     */
    async pollStatus(pollInterval = 2000, maxAttempts = null) {
        if (maxAttempts === null) {
            maxAttempts = Math.max(150, Math.ceil(this.file.size / (5 * 1024 * 1024)));
        }
        // Transient poll failures get their own budget so a few network blips
        // don't consume the assembly-progress budget. Resets on any successful
        // poll; ~30 consecutive failures with capped backoff means the server
        // has been unreachable for minutes and we give up.
        const maxConsecutiveErrors = 30;
        let consecutiveErrors = 0;
        // A 429 from /status means this client (or others behind the same
        // IP - NAT, Tor) polled too often, not that the server is down or the
        // upload failed: assembly carries on regardless. So it neither counts
        // toward maxConsecutiveErrors nor consumes assembly attempts; we just
        // poll more slowly. The status rate limit is an hourly window, so
        // only give up after being limited for longer than that - otherwise
        // the claim code (which only /status returns) would be lost for an
        // upload that actually succeeded.
        const maxRateLimitedMs = 70 * 60 * 1000;
        let rateLimitedSince = null;
        let attempts = 0;
        const startTime = Date.now();

        while (attempts < maxAttempts) {
            try {
                // Get current status
                const status = await this.getStatus();

                // Calculate elapsed time
                const elapsed = Math.round((Date.now() - startTime) / 1000);

                // Emit progress event for UI updates
                this.emit('assembling_progress', {
                    status: status.status,
                    uploadId: this.uploadId,
                    filename: status.filename,
                    attempts: attempts + 1,
                    maxAttempts: maxAttempts,
                    elapsedSeconds: elapsed,
                    // ADR-015: assembly now includes a synchronous malware
                    // scan before the file is stored, so this can legitimately
                    // take a while on a large file — say so rather than leave
                    // "Processing" looking stuck.
                    message: `Processing and scanning... (${elapsed}s elapsed)`
                });

                // Check status field
                if (status.status === 'completed') {
                    // Assembly complete - return result
                    if (!status.claim_code || !status.download_url) {
                        const error = new Error('Assembly completed but missing claim_code or download_url');
                        error.terminal = true;
                        throw error;
                    }

                    // Build complete response matching expected format
                    return {
                        claim_code: status.claim_code,
                        download_url: status.download_url,
                        original_filename: status.filename,
                        file_size: status.file_size,
                        expires_at: status.expires_at,
                        max_downloads: status.max_downloads,
                        completed_downloads: status.completed_downloads
                    };
                }

                if (status.status === 'failed') {
                    // ADR-016: a retryable failure (e.g. SCAN_UNAVAILABLE, a
                    // transient IO/DB error during assembly) doesn't have to
                    // be terminal — the chunks are still on the server, and
                    // POSTing /complete again reopens the upload and re-runs
                    // assembly. Bounded to a few attempts (_retryFailedAssembly)
                    // so a permanently broken server doesn't retry forever.
                    if (status.retryable && await this._retryFailedAssembly(status)) {
                        consecutiveErrors = 0;
                        await this.sleep(pollInterval);
                        attempts++;
                        continue;
                    }

                    // Terminal (not retryable, or the local retry budget is
                    // exhausted) - throw error
                    const error = new Error(status.error_message || 'File assembly failed');
                    error.terminal = true;
                    // ADR-015/ADR-016: machine-readable reason (e.g.
                    // MALWARE_DETECTED, SCAN_UNAVAILABLE, INTEGRITY_ERROR,
                    // ASSEMBLY_RETRIES_EXHAUSTED), when the server sent one, so
                    // the UI can show a purpose-specific message instead of the
                    // raw error_message text.
                    error.code = status.error_code || null;
                    throw error;
                }

                if (status.status === 'uploading') {
                    // Should not normally happen while polling (polling only
                    // starts after /complete already returned 202) — but
                    // defensively, if the row ever falls back to "uploading"
                    // underneath us, silently polling it forever would hang.
                    // Re-POST /complete (bounded, same budget/backoff as a
                    // retryable failure) rather than assume it's still
                    // progressing on its own.
                    if (await this._retryFailedAssembly(status)) {
                        consecutiveErrors = 0;
                        await this.sleep(pollInterval);
                        attempts++;
                        continue;
                    }
                    const error = new Error('Upload fell back to uploading state and could not be resumed');
                    error.terminal = true;
                    throw error;
                }

                // Status is still "processing" - continue polling
                // Wait before next poll
                consecutiveErrors = 0;
                rateLimitedSince = null;
                await this.sleep(pollInterval);
                attempts++;

            } catch (error) {
                // User cancelled — stop polling, don't retry as a network blip
                if (this._isCancellation(error)) {
                    throw error;
                }

                // Server reported a final outcome (failed status, bad completion):
                // rethrow immediately. Matching on message text missed the
                // server's actual failure messages, so real failures were
                // retried as network errors.
                if (error.terminal) {
                    throw this._reportError(error, { stage: 'assembly', error: error.message, code: error.code || null });
                }

                if (error.status === 429) {
                    if (rateLimitedSince === null) {
                        rateLimitedSince = Date.now();
                    } else if (Date.now() - rateLimitedSince > maxRateLimitedMs) {
                        throw this._reportError(
                            new Error('Assembly status polling was rate limited for over an hour'),
                            { stage: 'assembly_polling', error: error.message }
                        );
                    }
                    // Honour Retry-After within reason: the server's value is
                    // the whole window (an hour), far too long to wait for a
                    // claim code; 15-60s keeps well under the limit.
                    const waitSeconds = Math.min(Math.max(error.retryAfterSeconds || 0, 15), 60);
                    console.warn(`Status polling rate limited; retrying in ${waitSeconds}s`);
                    await this.sleep(waitSeconds * 1000);
                    continue;
                }

                // For network errors, retry with exponential backoff against a
                // separate budget (doesn't consume assembly-progress attempts)
                consecutiveErrors++;
                if (consecutiveErrors >= maxConsecutiveErrors) {
                    throw this._reportError(
                        new Error(`Assembly status polling failed after ${maxConsecutiveErrors} consecutive errors`),
                        { stage: 'assembly_polling', error: `Polling failed after ${maxConsecutiveErrors} consecutive errors: ${error.message}` }
                    );
                }

                // Exponential backoff for network errors (up to 10 seconds)
                const backoffDelay = Math.min(pollInterval * Math.pow(1.5, consecutiveErrors), 10000);
                console.warn(`Status polling attempt failed (${consecutiveErrors}/${maxConsecutiveErrors} consecutive), retrying in ${backoffDelay}ms...`, error.message);
                await this.sleep(backoffDelay);
            }
        }

        // Max attempts reached without completion
        const elapsedMinutes = Math.round((Date.now() - startTime) / 60000);
        throw new Error(`Assembly polling timed out after ${maxAttempts} attempts (${elapsedMinutes} minutes elapsed)`);
    }

    /**
     * ADR-016: reopen and retry a chunked upload whose assembly failed for a
     * retryable reason (SCAN_UNAVAILABLE, a transient IO/DB error, etc — see
     * status.retryable). POSTs /complete again, which the server accepts
     * for a retryable "failed" upload under its own attempt cap (re-running
     * missing-chunk repair too, via _postComplete). Bounded to a handful of
     * attempts across the whole polling session so a permanently broken
     * server doesn't retry forever.
     * @param {Object} status - the failed status payload from getStatus()
     * @returns {Promise<boolean>} true if the retry was accepted and polling
     *   should continue; false once the local retry budget is exhausted or
     *   the server itself refused (e.g. answered 409 terminal).
     */
    async _retryFailedAssembly(status) {
        const maxRetries = 3;
        this._assemblyRetryCount = (this._assemblyRetryCount || 0) + 1;
        if (this._assemblyRetryCount > maxRetries) {
            return false;
        }

        this.emit('assembling_retry', {
            uploadId: this.uploadId,
            attempt: this._assemblyRetryCount,
            maxRetries,
            code: status.error_code || null,
            message: status.error_message || null
        });

        const delay = Math.min(2000 * Math.pow(2, this._assemblyRetryCount - 1), 15000);
        console.warn(`Assembly failed (retryable, code: ${status.error_code || 'unknown'}); retrying completion ` +
            `(attempt ${this._assemblyRetryCount}/${maxRetries}) in ${delay}ms...`);
        await this.sleep(delay);

        try {
            await this._postComplete();
            return true;
        } catch (error) {
            if (this._isCancellation(error)) {
                throw error;
            }
            // A definitively terminal server response (retryRecommended
            // explicitly false — e.g. a 409 meaning attempts are exhausted
            // server-side too, or a non-retryable error code) means further
            // retries can't help; stop now. Anything else — a network blip,
            // or a transient 5xx that _postComplete's own internal backoff
            // didn't outlast — is still worth another attempt from here:
            // return true so the poll loop calls back into
            // _retryFailedAssembly on its next tick (status.retryable is
            // still true), which is what actually enforces the maxRetries
            // budget above. Bug-hunter finding (ADR-016 M2): returning false
            // on the very first _postComplete failure meant the outer
            // "retry up to 3 times" budget was never really usable — one
            // failed POST always gave up immediately instead of backing off
            // and retrying.
            if (error.retryRecommended === false) {
                return false;
            }
            return this._assemblyRetryCount < maxRetries;
        }
    }

    /**
     * Pause upload
     */
    pause() {
        this.isPaused = true;
        // Stop in-flight chunk requests instead of letting them keep
        // transferring; aborted chunks are re-uploaded on resume.
        if (this.abortController) {
            this.abortController.abort();
        }
        this.saveState();
        this.emit('paused', {
            uploadedChunks: this.uploadedChunks.size,
            totalChunks: this.totalChunks
        });
    }

    /**
     * Resume upload
     * @returns {Promise<void>}
     */
    async resume() {
        // A cancelled upload is gone for good (abort() sets isCompleted and
        // clears the saved state) — don't let resume restart it.
        if (this.isCompleted) return;

        this.isPaused = false;

        // Network conditions may have changed while paused (interface switch,
        // congestion cleared). Discard pre-pause latency data so calibration
        // restarts fresh instead of anchoring to a stale window.
        this.networkMetrics.recentLatencies = [];
        this.networkMetrics.avgLatency = 0;
        this.networkMetrics.baselineLatency = null;
        this.networkMetrics.latencyThreshold = this.networkMetrics.staticLatencyThreshold;
        this.networkMetrics.consecutiveSuccesses = 0;
        this.networkMetrics.consecutiveFailures = 0;

        this.emit('resumed', {
            uploadedChunks: this.uploadedChunks.size,
            totalChunks: this.totalChunks
        });

        // Continue uploading remaining chunks
        await this.uploadAllChunks();
    }

    /**
     * Abort/cancel upload
     * Stops all in-progress uploads and clears state
     */
    abort() {
        // No-op when the upload already finished (cancel landed just after
        // the final status poll returned 'completed' — the file exists and
        // results are already shown) or was already aborted.
        if (this.isCompleted) return;

        this.isPaused = true; // Stop new chunk uploads
        this.isCompleted = true; // Prevent resume

        // Abort in-flight chunk/status requests immediately
        if (this.abortController) {
            this.abortController.abort();
        }

        // Clear localStorage state
        if (this.storageKey) {
            try {
                localStorage.removeItem(this.storageKey);
            } catch (e) {
                console.warn('Failed to clear upload state from localStorage:', e);
            }
        }

        this.emit('cancelled', {
            uploadedChunks: this.uploadedChunks.size,
            totalChunks: this.totalChunks,
            uploadId: this.uploadId
        });
    }

    /**
     * Emit progress event with calculated metrics (throttled for performance)
     */
    emitProgress() {
        const now = Date.now();
        this.progressThrottle.chunksSinceLastEmit++;

        // Throttle: emit only if enough time passed OR enough chunks uploaded
        const timeSinceLastEmit = now - this.progressThrottle.lastEmit;
        const shouldEmit =
            timeSinceLastEmit >= this.progressThrottle.minInterval ||
            this.progressThrottle.chunksSinceLastEmit >= this.progressThrottle.chunkThreshold ||
            this.uploadedChunks.size === this.totalChunks;  // Always emit at 100%

        if (!shouldEmit) {
            return;
        }

        const percentage = (this.uploadedChunks.size / this.totalChunks) * 100;
        const elapsed = now - this.startTime;
        const bytesPerMs = this.uploadedBytes / elapsed;
        const remainingBytes = this.file.size - this.uploadedBytes;
        const estimatedTimeRemaining = remainingBytes / bytesPerMs;

        this.emit('progress', {
            uploadedChunks: this.uploadedChunks.size,
            totalChunks: this.totalChunks,
            uploadedBytes: this.uploadedBytes,
            totalBytes: this.file.size,
            percentage: Math.round(percentage * 100) / 100,
            estimatedTimeRemaining: Math.round(estimatedTimeRemaining / 1000), // in seconds
            speed: bytesPerMs * 1000, // bytes per second
            currentConcurrency: this.options.concurrency,  // Show current concurrency
            avgLatency: Math.round(this.networkMetrics.avgLatency) || 0  // Show network quality
        });

        // Reset throttle counters
        this.progressThrottle.lastEmit = now;
        this.progressThrottle.chunksSinceLastEmit = 0;
    }

    /**
     * Save upload state to localStorage for resume capability
     */
    saveState() {
        if (!this.storageKey || this.options.persistState === false) return;

        // Never persist the upload password: it is only needed for /init, and
        // localStorage is plaintext that outlives failed uploads.
        const { password, ...persistedOptions } = this.options;

        const state = {
            uploadId: this.uploadId,
            filename: this.file.name,
            fileSize: this.file.size,
            chunkSize: this.chunkSize,
            totalChunks: this.totalChunks,
            uploadedChunks: Array.from(this.uploadedChunks),
            uploadedBytes: this.uploadedBytes,
            startTime: this.startTime,
            options: persistedOptions,
            isPaused: this.isPaused
        };

        try {
            localStorage.setItem(this.storageKey, JSON.stringify(state));
        } catch (e) {
            console.warn('Failed to save upload state to localStorage:', e);
        }
    }

    /**
     * Load upload state from localStorage
     * @param {string} uploadId - Upload ID to resume
     * @returns {Object|null} - Saved state or null if not found
     */
    static loadState(uploadId) {
        const storageKey = `chunked_upload_${uploadId}`;

        try {
            const stateJson = localStorage.getItem(storageKey);
            if (!stateJson) return null;

            return JSON.parse(stateJson);
        } catch (e) {
            console.warn('Failed to load upload state from localStorage:', e);
            return null;
        }
    }

    /**
     * Resume from saved state
     * @param {File} file - The same file object
     * @param {string} uploadId - Upload ID to resume
     * @returns {ChunkedUploader|null} - Restored uploader or null if not found
     */
    static resumeFromState(file, uploadId) {
        const state = ChunkedUploader.loadState(uploadId);
        if (!state) return null;

        // Verify file matches
        if (file.name !== state.filename || file.size !== state.fileSize) {
            console.error('File mismatch: cannot resume upload');
            return null;
        }

        // Create uploader instance
        const uploader = new ChunkedUploader(file, state.options);
        uploader.uploadId = state.uploadId;
        uploader.chunkSize = state.chunkSize;
        uploader.totalChunks = state.totalChunks;
        uploader.uploadedChunks = new Set(state.uploadedChunks);
        uploader.uploadedBytes = state.uploadedBytes;
        uploader.startTime = state.startTime;
        uploader.isPaused = state.isPaused;
        uploader.storageKey = `chunked_upload_${uploadId}`;

        return uploader;
    }

    /**
     * Clear saved state from localStorage
     */
    clearState() {
        if (!this.storageKey) return;

        try {
            localStorage.removeItem(this.storageKey);
        } catch (e) {
            console.warn('Failed to clear upload state from localStorage:', e);
        }
    }

    /**
     * Delete every saved resume state (they contain filenames). Used in Ghost mode.
     */
    static clearAllSavedUploads() {
        try {
            const keys = [];
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && key.startsWith('chunked_upload_')) keys.push(key);
            }
            keys.forEach(key => localStorage.removeItem(key));
        } catch (e) {
            console.warn('Failed to clear saved upload states:', e);
        }
    }

    /**
     * Remove passwords from upload states saved by earlier versions, which
     * persisted the full options object (including the password) in plaintext.
     */
    static scrubSavedPasswords() {
        try {
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (!key || !key.startsWith('chunked_upload_')) continue;
                const state = JSON.parse(localStorage.getItem(key) || 'null');
                if (state && state.options && 'password' in state.options) {
                    delete state.options.password;
                    localStorage.setItem(key, JSON.stringify(state));
                }
            }
        } catch (e) {
            console.warn('Failed to scrub saved upload passwords:', e);
        }
    }

    /**
     * List all saved uploads in localStorage
     * @returns {Array<Object>} - Array of saved upload states
     */
    static listSavedUploads() {
        const uploads = [];

        try {
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && key.startsWith('chunked_upload_')) {
                    const stateJson = localStorage.getItem(key);
                    if (stateJson) {
                        const state = JSON.parse(stateJson);
                        uploads.push({
                            uploadId: state.uploadId,
                            filename: state.filename,
                            fileSize: state.fileSize,
                            progress: (state.uploadedChunks.length / state.totalChunks) * 100,
                            uploadedChunks: state.uploadedChunks.length,
                            totalChunks: state.totalChunks,
                            isPaused: state.isPaused,
                            startTime: state.startTime
                        });
                    }
                }
            }
        } catch (e) {
            console.warn('Failed to list saved uploads:', e);
        }

        return uploads;
    }

    /**
     * Calculate SHA256 checksum of a Blob using Web Crypto API
     * @param {Blob} blob - The blob to hash
     * @returns {Promise<string>} - Hex-encoded SHA256 hash
     */
    async _calculateChecksum(blob) {
        // Check if crypto.subtle is available (requires secure context: HTTPS or localhost)
        if (!crypto || !crypto.subtle || !crypto.subtle.digest) {
            console.warn('Web Crypto API not available (requires HTTPS or localhost). Skipping client-side checksum.');
            return null; // Return null to indicate checksum unavailable
        }

        const arrayBuffer = await blob.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    /**
     * Emit 'error' for a failure and mark the error as reported, so outer
     * layers (complete()'s catch, the page's own catch) don't report the same
     * failure again — one failure used to produce up to three toasts.
     * @returns {Error} the same error, for `throw this._reportError(...)`
     */
    _reportError(error, data) {
        if (!error.reported) {
            this.emit('error', data);
            error.reported = true;
        }
        return error;
    }

    /**
     * Error representing a user-initiated cancel/pause. Marked so retry
     * loops and error handlers can tell it apart from real failures.
     */
    _cancellationError() {
        const error = new Error('Upload cancelled');
        error.isCancellation = true;
        return error;
    }

    /**
     * True for our own cancellation errors and for fetch() AbortErrors
     * produced when pause()/abort() aborts the shared AbortController.
     */
    _isCancellation(error) {
        return error.isCancellation === true || error.name === 'AbortError';
    }

    /**
     * POST /complete, retrying transient failures. The endpoint is safe to
     * repeat: once the server has started assembling it answers 202/200 again.
     * Handles 503 ASSEMBLY_BUSY (honoring Retry-After), 5xx from proxies, and
     * network drops, and re-uploads any chunks the server reports missing.
     * Giving up here used to throw away a fully uploaded file (and, for E2E
     * uploads, the only copy of its key).
     * @returns {Promise<Response>} - A 2xx response
     */
    async _postComplete() {
        const maxAttempts = 8;
        let reuploadedMissing = false;

        for (let attempt = 1; ; attempt++) {
            let error;
            try {
                const response = await fetch(`/api/upload/complete/${this.uploadId}`, {
                    method: 'POST',
                    signal: this.abortController ? this.abortController.signal : undefined
                });
                if (response.ok) {
                    return response;
                }
                error = await this.parseErrorResponse(response);
            } catch (fetchError) {
                if (this._isCancellation(fetchError)) {
                    throw fetchError;
                }
                error = fetchError; // network failure: retryable
            }

            if (error.missingChunks && error.missingChunks.length > 0 && !reuploadedMissing) {
                // Chunks the server doesn't have (e.g. lost to a failed write):
                // upload them again once, then retry completion.
                reuploadedMissing = true;
                console.warn(`Server is missing ${error.missingChunks.length} chunk(s); re-uploading before completing`);
                error.missingChunks.forEach(chunk => {
                    if (this.uploadedChunks.delete(chunk)) {
                        const start = chunk * this.chunkSize;
                        this.uploadedBytes -= Math.min(this.chunkSize, this.file.size - start);
                    }
                });
                await this.uploadAllChunks();
                continue; // the repair uses one of the maxAttempts; 7 remain for completion
            }

            if (error.retryRecommended === false || this._retryAfterTooLong(error) || attempt >= maxAttempts) {
                throw error;
            }

            const delay = this._retryDelay(attempt, error.retryAfter);
            console.warn(`Completing upload failed (attempt ${attempt}/${maxAttempts}, code: ${error.code || 'NETWORK_ERROR'}), retrying in ${delay}ms...`);
            await this._waitForOnline();
            await this.sleep(delay);
        }
    }

    /**
     * Whether an HTTP status is worth retrying: timeouts, rate limits and
     * server/proxy errors. Other 4xx responses won't change on retry, nor will
     * 501/505/507 (not implemented, bad HTTP version, out of storage).
     */
    static isRetryableStatus(status) {
        if (status === 408 || status === 425 || status === 429) return true;
        return status >= 500 && status !== 501 && status !== 505 && status !== 507;
    }

    /**
     * Backoff before retry `attempt` (1-based). Honors a server-provided delay;
     * otherwise exponential from options.retryDelay with "equal jitter" (a
     * random delay between half and all of the backoff), so parallel chunk
     * workers don't retry in lockstep and no retry fires almost immediately.
     */
    _retryDelay(attempt, retryAfterSeconds) {
        const cap = this.options.maxRetryDelay;
        if (retryAfterSeconds) {
            return Math.min(retryAfterSeconds * 1000, cap);
        }
        const exp = Math.min(this.options.retryDelay * Math.pow(2, attempt - 1), cap);
        return Math.round(exp / 2 + Math.random() * exp / 2);
    }

    /** A server-requested wait longer than a minute means give up, not sleep. */
    _retryAfterTooLong(error) {
        return !!error.retryAfter && error.retryAfter > 60;
    }

    /**
     * If the browser reports being offline, wait until it's back before
     * retrying instead of burning retry attempts. Cancellable via pause()/abort().
     */
    _waitForOnline() {
        if (typeof navigator === 'undefined' || navigator.onLine !== false) {
            return Promise.resolve();
        }
        const signal = this.abortController ? this.abortController.signal : null;
        return new Promise((resolve, reject) => {
            const cleanup = () => {
                window.removeEventListener('online', onOnline);
                if (signal) signal.removeEventListener('abort', onAbort);
            };
            const onOnline = () => { cleanup(); resolve(); };
            const onAbort = () => { cleanup(); reject(this._cancellationError()); };
            if (signal && signal.aborted) {
                reject(this._cancellationError());
                return;
            }
            window.addEventListener('online', onOnline);
            if (signal) signal.addEventListener('abort', onAbort);
        });
    }

    /**
     * Custom error class that includes retry recommendations
     */
    createRetryableError(message, code, retryRecommended, retryAfter) {
        const error = new Error(message);
        error.code = code;
        error.retryRecommended = retryRecommended;
        error.retryAfter = retryAfter;
        return error;
    }

    /**
     * Track successful chunk upload and adjust concurrency
     */
    _trackUploadSuccess(latency) {
        this.networkMetrics.consecutiveSuccesses++;
        this.networkMetrics.consecutiveFailures = 0;

        // Track latency (keep last 10)
        this.networkMetrics.recentLatencies.push(latency);
        if (this.networkMetrics.recentLatencies.length > 10) {
            this.networkMetrics.recentLatencies.shift();
        }

        // Anchor the degradation baseline (Guard 2) to the median of the first
        // three samples rather than the first chunk alone: chunk #1 is often an
        // outlier (cold connection/TLS warmup makes it slow; an idle server
        // makes it anomalously fast), and a too-fast anchor would make the
        // 1.5x degradation guard freeze concurrency for the entire upload.
        if (this.networkMetrics.baselineLatency === null && this.networkMetrics.recentLatencies.length >= 3) {
            const firstThree = this.networkMetrics.recentLatencies.slice(0, 3).sort((a, b) => a - b);
            this.networkMetrics.baselineLatency = firstThree[1];
            console.log('Baseline latency established (median of first 3 chunks):', firstThree[1] + 'ms');
        }

        // Calculate average latency
        this.networkMetrics.avgLatency =
            this.networkMetrics.recentLatencies.reduce((a, b) => a + b, 0) /
            this.networkMetrics.recentLatencies.length;

        // Recalibrate the latency ceiling to the observed link speed. The
        // static threshold assumes a >=10 Mbps uplink; on slower links every
        // chunk exceeds it and Guard 1 would freeze the controller for the
        // whole upload. min(recent) approximates the link's best uncongested
        // latency, so 2x that is a realistic ceiling. max() keeps the static
        // value as a floor so fast links behave exactly as before.
        // Note: if fast early samples slide out of the 10-sample window the
        // ceiling can rise; Guards 2/3 (baseline-relative + trend) remain the
        // primary congestion detectors. Below 3 samples the static threshold
        // applies unchanged.
        if (this.networkMetrics.recentLatencies.length >= 3) {
            this.networkMetrics.latencyThreshold = Math.max(
                this.networkMetrics.staticLatencyThreshold,
                Math.min(...this.networkMetrics.recentLatencies) * 2
            );
        }

        // Check if we should adjust concurrency after N consecutive successes
        if (this.networkMetrics.consecutiveSuccesses >= this.networkMetrics.adjustmentThreshold) {
            // ✅ LATENCY-AWARE DECISION MAKING

            // Guard 1: Don't increase if average latency exceeds threshold
            if (this.networkMetrics.avgLatency > this.networkMetrics.latencyThreshold) {
                console.log(`Skipping concurrency increase: avgLatency (${Math.round(this.networkMetrics.avgLatency)}ms) exceeds threshold (${this.networkMetrics.latencyThreshold}ms)`);
                this.networkMetrics.consecutiveSuccesses = 0;
                return;
            }

            // Guard 2: Don't increase if latency has degraded significantly from
            // baseline (skipped until the median-of-3 baseline is anchored)
            if (this.networkMetrics.baselineLatency !== null) {
                const latencyIncrease = (this.networkMetrics.avgLatency - this.networkMetrics.baselineLatency) / this.networkMetrics.baselineLatency;
                if (latencyIncrease > this.networkMetrics.latencyDegradationLimit) {
                    console.log(`Skipping concurrency increase: latency degraded ${Math.round(latencyIncrease * 100)}% from baseline (limit: ${this.networkMetrics.latencyDegradationLimit * 100}%)`);
                    this.networkMetrics.consecutiveSuccesses = 0;
                    return;
                }
            }

            // Guard 3: Don't increase if latency is trending worse
            const latencyTrend = this._calculateLatencyTrend();
            if (latencyTrend > 0.15) {  // More than 15% increase trend
                console.log(`Skipping concurrency increase: latency trending worse (+${Math.round(latencyTrend * 100)}%)`);
                this.networkMetrics.consecutiveSuccesses = 0;
                return;
            }

            // All guards passed - safe to increase concurrency
            this._adjustConcurrency('increase');
            this.networkMetrics.consecutiveSuccesses = 0;
        }

        // ✅ PROACTIVE DECREASE: Check if latency is degrading even without failures
        if (this.networkMetrics.recentLatencies.length >= 5) {
            const latencyTrend = this._calculateLatencyTrend();

            // If latency is rapidly increasing (>30% trend), proactively decrease
            if (latencyTrend > 0.3) {
                console.log(`Proactive concurrency decrease: latency rapidly increasing (+${Math.round(latencyTrend * 100)}%)`);
                this._adjustConcurrency('decrease');
                this.networkMetrics.consecutiveSuccesses = 0;
            }
        }
    }

    /**
     * Track failed chunk upload and adjust concurrency
     */
    _trackUploadFailure() {
        this.networkMetrics.consecutiveFailures++;
        this.networkMetrics.consecutiveSuccesses = 0;

        // Decrease concurrency after N consecutive failures
        if (this.networkMetrics.consecutiveFailures >= this.networkMetrics.adjustmentThreshold) {
            this._adjustConcurrency('decrease');
            this.networkMetrics.consecutiveFailures = 0;
        }
    }

    /**
     * Calculate latency trend (positive = getting slower, negative = getting faster)
     * Uses linear regression on recent latencies to detect trends
     * @returns {number} - Percentage change (-1.0 = improving 100%, +1.0 = degrading 100%)
     */
    _calculateLatencyTrend() {
        const latencies = this.networkMetrics.recentLatencies;
        if (latencies.length < 3) {
            return 0; // Not enough data
        }

        // Simple linear regression to detect trend
        // Compare average of first half vs second half
        const midpoint = Math.floor(latencies.length / 2);
        const firstHalf = latencies.slice(0, midpoint);
        const secondHalf = latencies.slice(midpoint);

        const firstAvg = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
        const secondAvg = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;

        // Return percentage change (positive = getting worse, negative = getting better)
        return (secondAvg - firstAvg) / firstAvg;
    }

    /**
     * Adjust upload concurrency based on network performance
     */
    _adjustConcurrency(direction) {
        const oldConcurrency = this.options.concurrency;

        if (direction === 'increase') {
            // Good network - increase concurrency by 20%
            this.options.concurrency = Math.min(
                Math.ceil(this.options.concurrency * 1.2),
                this.networkMetrics.maxConcurrency
            );
        } else if (direction === 'decrease') {
            // Poor network - decrease concurrency by 30%
            this.options.concurrency = Math.max(
                Math.floor(this.options.concurrency * 0.7),
                this.networkMetrics.minConcurrency
            );
        }

        if (oldConcurrency !== this.options.concurrency) {
            console.log(`Adaptive concurrency: ${oldConcurrency} → ${this.options.concurrency} (${direction}, avg latency: ${Math.round(this.networkMetrics.avgLatency)}ms)`);

            this.emit('concurrency_adjusted', {
                oldConcurrency,
                newConcurrency: this.options.concurrency,
                direction,
                avgLatency: Math.round(this.networkMetrics.avgLatency),
                consecutiveSuccesses: this.networkMetrics.consecutiveSuccesses,
                consecutiveFailures: this.networkMetrics.consecutiveFailures
            });
        }
    }

    /**
     * Parse error response and extract retry information
     */
    async parseErrorResponse(response) {
        // Proxies answer 502/504 with HTML, so the body may not be JSON.
        const body = await response.json().catch(() => ({}));

        // Server hint wins; otherwise decide from the status code. Defaulting
        // to "retry every error after 5s" retried 404/410/413 pointlessly and
        // meant exponential backoff never ran.
        const retryRecommended = body.retry_recommended !== undefined
            ? body.retry_recommended
            : ChunkedUploader.isRetryableStatus(response.status);

        let retryAfter = body.retry_after || null;
        if (!retryAfter) {
            const header = parseInt(response.headers.get('Retry-After'), 10);
            retryAfter = Number.isFinite(header) && header > 0 ? header : null;
        }

        const error = this.createRetryableError(
            body.error || `Request failed (HTTP ${response.status})`,
            body.code || `HTTP_${response.status}`,
            retryRecommended,
            retryAfter
        );
        error.status = response.status;
        if (Array.isArray(body.missing_chunks)) {
            error.missingChunks = body.missing_chunks;
        }
        return error;
    }

    /**
     * Sleep utility. Rejects with a cancellation error if pause()/abort()
     * fires mid-sleep, so retry backoffs and poll intervals don't delay
     * cancellation by up to their full duration.
     * @param {number} ms - Milliseconds to sleep
     * @returns {Promise<void>}
     */
    sleep(ms) {
        const signal = this.abortController ? this.abortController.signal : null;
        return new Promise((resolve, reject) => {
            if (signal && signal.aborted) {
                reject(this._cancellationError());
                return;
            }
            const onAbort = () => {
                clearTimeout(id);
                reject(this._cancellationError());
            };
            const id = setTimeout(() => {
                if (signal) signal.removeEventListener('abort', onAbort);
                resolve();
            }, ms);
            if (signal) signal.addEventListener('abort', onAbort, { once: true });
        });
    }

    /**
     * Get upload progress summary
     * @returns {Object} - Progress summary
     */
    getProgress() {
        const percentage = (this.uploadedChunks.size / this.totalChunks) * 100;

        return {
            uploadedChunks: this.uploadedChunks.size,
            totalChunks: this.totalChunks,
            percentage: Math.round(percentage * 100) / 100,
            isPaused: this.isPaused,
            isCompleted: this.isCompleted
        };
    }

    /*
     * "Recent uploads on this device": a quiet list for anonymous uploaders,
     * so a claim code isn't lost if the tab is closed before it's copied.
     * Signed-in users have My Uploads instead, so nothing is stored for them.
     * Entries leave the list when the file expires.
     */
    static get RECENT_UPLOADS_KEY() { return 'safeshare_recent_uploads'; }

    // Kept for 30 days when the file never expires
    static get RECENT_UPLOADS_NO_EXPIRY_MS() { return 30 * 24 * 60 * 60 * 1000; }

    static get RECENT_UPLOADS_MAX() { return 20; }

    /**
     * Expiry time of an entry, or null when the file never expires (the
     * server sends "never" as ~100 years out, same cut-off as formatDate)
     * @returns {number|null}
     */
    static recentUploadExpiry(upload) {
        const expires = upload && upload.expires_at ? Date.parse(upload.expires_at) : NaN;
        if (Number.isNaN(expires)) return null;
        const NINETY_YEARS_MS = 90 * 365 * 24 * 60 * 60 * 1000;
        return expires - Date.now() > NINETY_YEARS_MS ? null : expires;
    }

    /**
     * Remember an upload in this browser's recent list
     * @param {Object} data - Upload response from the server
     */
    static saveRecentUpload(data) {
        if (!data || !data.claim_code) return;
        const entry = {
            claim_code: data.claim_code,
            download_url: data.download_url,
            filename: data.original_filename,
            file_size: data.file_size,
            expires_at: data.expires_at || null,
            saved_at: Date.now()
        };
        const list = ChunkedUploader.getRecentUploads()
            .filter(u => u.claim_code !== entry.claim_code);
        list.unshift(entry);
        ChunkedUploader.writeRecentUploads(list.slice(0, ChunkedUploader.RECENT_UPLOADS_MAX));
    }

    /**
     * Recent uploads that haven't expired, newest first
     * @returns {Array<Object>}
     */
    static getRecentUploads() {
        let list;
        try {
            list = JSON.parse(localStorage.getItem(ChunkedUploader.RECENT_UPLOADS_KEY) || '[]');
        } catch (e) {
            return [];
        }
        if (!Array.isArray(list)) return [];

        const now = Date.now();
        const live = list.filter(u => {
            if (!u || typeof u.claim_code !== 'string') return false;
            const expires = ChunkedUploader.recentUploadExpiry(u);
            if (expires !== null) return expires > now;
            return (Number(u.saved_at) || 0) + ChunkedUploader.RECENT_UPLOADS_NO_EXPIRY_MS > now;
        });
        if (live.length !== list.length) ChunkedUploader.writeRecentUploads(live);
        return live;
    }

    /**
     * Forget one upload
     * @param {string} claimCode
     */
    static removeRecentUpload(claimCode) {
        ChunkedUploader.writeRecentUploads(
            ChunkedUploader.getRecentUploads().filter(u => u.claim_code !== claimCode));
    }

    /**
     * Forget every recent upload, including the list kept by older versions
     */
    static clearRecentUploads() {
        try {
            localStorage.removeItem(ChunkedUploader.RECENT_UPLOADS_KEY);
        } catch (e) { /* storage blocked */ }
        ChunkedUploader.dropLegacyCompletions();
    }

    /**
     * Older versions kept every claim code for 7 days and showed them in a
     * pop-up on each visit (even to the next person on a shared computer).
     * That list is deleted rather than migrated.
     */
    static dropLegacyCompletions() {
        try {
            localStorage.removeItem('safeshare_completed_uploads');
        } catch (e) { /* storage blocked */ }
    }

    static writeRecentUploads(list) {
        try {
            if (list.length) {
                localStorage.setItem(ChunkedUploader.RECENT_UPLOADS_KEY, JSON.stringify(list));
            } else {
                localStorage.removeItem(ChunkedUploader.RECENT_UPLOADS_KEY);
            }
        } catch (e) {
            console.warn('Failed to update recent uploads:', e);
        }
    }
}