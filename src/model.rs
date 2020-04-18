#[derive(Clone, Debug, Default)]
pub struct Machine {
    pub resolution: (u32, u32),
    pub volume_mm: (f32, f32, f32),
    pub machine_type: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Job {
    pub layer_height_mm: f32,
    pub bottom_layer_count: u32,
    pub retract_speed_mmps: f32,

    pub normal: LayerConfig,
    pub bottom: LayerConfig,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct LayerConfig {
    pub exposure_s: f32,
    pub light_off_time_s: f32,
    pub lift_dist_mm: f32,
    pub lift_speed_mmps: f32,
}

#[derive(Clone, Debug)]
pub struct Resin {
    pub g_per_ml: f32,
    pub cost: ResinCost,
}

#[derive(Copy, Clone, Debug)]
pub enum ResinCost {
    PerGram(f32),
    PerMl(f32),
}
