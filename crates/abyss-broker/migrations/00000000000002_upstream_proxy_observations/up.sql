ALTER TABLE network_observations ADD COLUMN destination_addr TEXT;
ALTER TABLE network_observations ADD COLUMN proxy_endpoint TEXT;
ALTER TABLE network_observations ADD COLUMN proxy_peer TEXT;
ALTER TABLE network_observations ADD COLUMN proxy_status INTEGER;
ALTER TABLE network_observations ADD COLUMN target_authority TEXT;
