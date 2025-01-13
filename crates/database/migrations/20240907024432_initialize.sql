-- Must be sqlite3 compatible

CREATE TABLE uploads (
    id BLOB PRIMARY KEY NOT NULL, -- UUID

    upload_key VARCHAR(8) NOT NULL,

    uploader_username VARCHAR(255) NOT NULL,

    file_name_on_disk BLOB, -- UUID
    file_name VARCHAR(255) NOT NULL,
    file_size INT NOT NULL,

    -- Timestamps should be in UTC timezone
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    uploaded_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX idx_uploads_upload_key ON uploads(upload_key);
CREATE INDEX idx_file_name_on_disk ON uploads(file_name_on_disk);
-- Ensure that only one non-expired/deleted upload exists for a given upload_id at a time.
CREATE UNIQUE INDEX idx_uploads_upload_id_deleted_at ON uploads(upload_key) WHERE deleted_at IS NULL;

-- Create triggers that will prevent updates to the created_at property.
CREATE TRIGGER prevent_update_uploads_created_at
BEFORE UPDATE OF created_at ON uploads
BEGIN
    SELECT RAISE(FAIL, 'created_at is read-only');
END;

-- Create triggers that will prevent updates to the expires_at property.
CREATE TRIGGER prevent_update_uploads_expires_at
BEFORE UPDATE OF expires_at ON uploads
BEGIN
    SELECT RAISE(FAIL, 'expires_at is read-only');
END;

-- Create triggers that will auto-update the updated_at property.
CREATE TRIGGER update_uploads_updated_at
AFTER UPDATE ON uploads
FOR EACH ROW
BEGIN
    UPDATE uploads SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Create trigger that will prevent hard deletes.
CREATE TRIGGER prevent_delete_uploads
BEFORE DELETE ON uploads
BEGIN
    SELECT RAISE(FAIL, 'deleting uploads is not allowed');
END;
