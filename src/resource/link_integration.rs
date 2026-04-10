// Link integration: extension methods for Resource support on Link

use crate::link::link::Link;
use crate::Result;

impl Link {
    /// Register an incoming resource on this link.
    pub fn register_incoming_resource(&self, hash: [u8; 32]) -> Result<()> {
        let mut inner = self.write()?;
        if !inner.incoming_resources.contains(&hash) {
            inner.incoming_resources.push(hash);
        }
        Ok(())
    }

    /// Register an outgoing resource on this link.
    pub fn register_outgoing_resource(&self, hash: [u8; 32]) -> Result<()> {
        let mut inner = self.write()?;
        if !inner.outgoing_resources.contains(&hash) {
            inner.outgoing_resources.push(hash);
        }
        Ok(())
    }

    /// Cancel an incoming resource by removing it from the registry.
    pub fn cancel_incoming_resource(&self, hash: &[u8; 32]) -> Result<()> {
        let mut inner = self.write()?;
        inner.incoming_resources.retain(|h| h != hash);
        Ok(())
    }

    /// Cancel an outgoing resource by removing it from the registry.
    pub fn cancel_outgoing_resource(&self, hash: &[u8; 32]) -> Result<()> {
        let mut inner = self.write()?;
        inner.outgoing_resources.retain(|h| h != hash);
        Ok(())
    }

    /// Notify that a resource has concluded (remove from both registries).
    pub fn resource_concluded(&self, hash: &[u8; 32]) -> Result<()> {
        let mut inner = self.write()?;
        inner.incoming_resources.retain(|h| h != hash);
        inner.outgoing_resources.retain(|h| h != hash);
        Ok(())
    }

    /// Check if the link is ready for a new outgoing resource.
    /// Returns true when no outgoing resource is currently registered.
    pub fn ready_for_new_resource(&self) -> Result<bool> {
        let inner = self.read()?;
        Ok(inner.outgoing_resources.is_empty())
    }

    /// Check if an incoming resource with this hash exists.
    pub fn has_incoming_resource(&self, hash: &[u8; 32]) -> Result<bool> {
        let inner = self.read()?;
        Ok(inner.incoming_resources.contains(hash))
    }

    /// Store the last resource window size for warm-starting.
    pub fn set_last_resource_window(&self, window: usize) -> Result<()> {
        let mut inner = self.write()?;
        inner.last_resource_window = Some(window);
        Ok(())
    }

    /// Retrieve the last resource window size.
    pub fn get_last_resource_window(&self) -> Result<Option<usize>> {
        let inner = self.read()?;
        Ok(inner.last_resource_window)
    }

    /// Store the last resource EIFR for warm-starting.
    pub fn set_last_resource_eifr(&self, eifr: f64) -> Result<()> {
        let mut inner = self.write()?;
        inner.last_resource_eifr = Some(eifr);
        Ok(())
    }

    /// Retrieve the last resource EIFR.
    pub fn get_last_resource_eifr(&self) -> Result<Option<f64>> {
        let inner = self.read()?;
        Ok(inner.last_resource_eifr)
    }
}
