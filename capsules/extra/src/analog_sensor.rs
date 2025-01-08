// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Capsule for analog sensors.
//!
//! This capsule provides the sensor HIL interfaces for sensors which only need
//! an ADC.
//!
//! It includes support for analog light sensors and analog temperature sensors.

use kernel::hil;
use kernel::utilities::cells::OptionalCell;
use kernel::ErrorCode;

/// The type of the sensor implies how the raw ADC reading should be converted
/// to a light value.
pub enum AnalogLightSensorType {
    LightDependentResistor,
}

pub struct AnalogLightSensor<'a, A: hil::adc::Adc<'a>> {
    adc: &'a A,
    channel: &'a <A as hil::adc::Adc<'a>>::Channel,
    sensor_type: AnalogLightSensorType,
    client: OptionalCell<&'a dyn hil::sensors::AmbientLightClient>,
}

impl<'a, A: hil::adc::Adc<'a>> AnalogLightSensor<'a, A> {
    pub fn new(
        adc: &'a A,
        channel: &'a <A as kernel::hil::adc::Adc<'a>>::Channel,
        sensor_type: AnalogLightSensorType,
    ) -> AnalogLightSensor<'a, A> {
        AnalogLightSensor {
            adc,
            channel,
            sensor_type,
            client: OptionalCell::empty(),
        }
    }
}

/// Callbacks from the ADC driver
impl<'a, A: hil::adc::Adc<'a>> hil::adc::Client for AnalogLightSensor<'a, A> {
    fn sample_ready(&self, sample: u16) {
        // TODO: calculate the actual light reading.
        let measurement: usize = match self.sensor_type {
            AnalogLightSensorType::LightDependentResistor => {
                // TODO: need to determine the actual value that the 5000 should be
                (sample as usize * 5000) / 65535
            }
        };
        self.client.map(|client| client.callback(measurement));
    }
}

impl<'a, A: hil::adc::Adc<'a>> hil::sensors::AmbientLight<'a> for AnalogLightSensor<'a, A> {
    fn set_client(&self, client: &'a dyn hil::sensors::AmbientLightClient) {
        self.client.set(client);
    }

    fn read_light_intensity(&self) -> Result<(), ErrorCode> {
        self.adc.sample(self.channel)
    }
}

/// The type of the sensor implies how the raw ADC reading should be converted
/// to a temperature value.
pub enum AnalogTemperatureSensorType {
    MicrochipMcp9700,
}

pub struct AnalogTemperatureSensor<'a, A: hil::adc::Adc<'a>> {
    adc: &'a A,
    channel: &'a <A as hil::adc::Adc<'a>>::Channel,
    sensor_type: AnalogTemperatureSensorType,
    client: OptionalCell<&'a dyn hil::sensors::TemperatureClient>,
}

impl<'a, A: hil::adc::Adc<'a>> AnalogTemperatureSensor<'a, A> {
    pub fn new(
        adc: &'a A,
        channel: &'a <A as kernel::hil::adc::Adc<'a>>::Channel,
        sensor_type: AnalogLightSensorType,
    ) -> AnalogLightSensor<'a, A> {
        AnalogLightSensor {
            adc,
            channel,
            sensor_type,
            client: OptionalCell::empty(),
        }
    }
}

/// Callbacks from the ADC driver
impl<'a, A: hil::adc::Adc<'a>> hil::adc::Client for AnalogTemperatureSensor<'a, A> {
    fn sample_ready(&self, sample: u16) {
        // TODO: calculate the actual temperature reading.
        let measurement = match self.sensor_type {
            // 𝑉out = 500𝑚𝑉 + 10𝑚𝑉/C ∗ 𝑇A
            AnalogTemperatureSensorType::MicrochipMcp9700 => {
                self.adc
                    .get_voltage_reference_mv()
                    .map_or(Err(ErrorCode::FAIL), |ref_mv| {
                        // reading_mv = (ADC / (2^16-1)) * ref_voltage
                        let reading_mv = (sample as usize * ref_mv) / 65535;
                        // need 0.01°C
                        Ok((reading_mv as i32 - 500) * 10)
                    })
            }
        };
        self.client.map(|client| client.callback(measurement));
    }
}

impl<'a, A: hil::adc::Adc<'a>> hil::sensors::TemperatureDriver<'a>
    for AnalogTemperatureSensor<'a, A>
{
    fn set_client(&self, client: &'a dyn hil::sensors::TemperatureClient) {
        self.client.set(client);
    }

    fn read_temperature(&self) -> Result<(), ErrorCode> {
        self.adc.sample(self.channel)
    }
}
