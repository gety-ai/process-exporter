pub struct Gpu {}

impl Gpu {
    pub fn new(pid: u32) -> Result<Self, anyhow::Error> {
        Ok(Self {})
    }

    pub fn is_active(&self) -> bool {
        false
    }

    pub fn sample(&self) -> f64 {
        0.0
    }
}

