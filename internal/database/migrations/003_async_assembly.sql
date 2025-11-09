-- Add status tracking for async assembly
ALTER TABLE partial_uploads ADD COLUMN status TEXT NOT NULL DEFAULT 'uploading';
ALTER TABLE partial_uploads ADD COLUMN error_message TEXT;
ALTER TABLE partial_uploads ADD COLUMN assembly_started_at TIMESTAMP;
ALTER TABLE partial_uploads ADD COLUMN assembly_completed_at TIMESTAMP;

-- Create index on status for querying processing uploads
CREATE INDEX IF NOT EXISTS idx_partial_uploads_status ON partial_uploads(status);
