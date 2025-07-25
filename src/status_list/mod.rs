use base64::{engine::general_purpose, Engine as _};
use flate2::write::ZlibEncoder;
use flate2::{read::ZlibDecoder, Compression};
use serde::{Deserialize, Serialize};
use std::io::prelude::*;
use ts_rs::TS;

use crate::error::OAuthTSLError;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum Bits {
    #[default]
    One = 1,
    Two = 2,
    Four = 4,
    Eight = 8,
}

impl TryFrom<u8> for Bits {
    type Error = OAuthTSLError;

    fn try_from(value: u8) -> Result<Self, OAuthTSLError> {
        match value {
            1 => Ok(Bits::One),
            2 => Ok(Bits::Two),
            4 => Ok(Bits::Four),
            8 => Ok(Bits::Eight),
            _ => Err(OAuthTSLError::InvalidStatusSize(value as usize)),
        }
    }
}

impl Bits {
    pub fn as_u8(&self) -> u8 {
        self.clone() as u8
    }

    pub fn as_usize(&self) -> usize {
        match self {
            Bits::One => 1,
            Bits::Two => 2,
            Bits::Four => 4,
            Bits::Eight => 8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncodedStatusList {
    #[serde(rename = "bits")]
    pub status_size: u8,
    #[serde(rename = "lst")]
    pub status_list: String,
    // todo: not implemented yet
    pub aggregation_uri: Option<String>,
}

impl Default for EncodedStatusList {
    fn default() -> Self {
        EncodedStatusList {
            status_size: Bits::Two.as_u8(),
            status_list: String::new(),
            aggregation_uri: None,
        }
    }
}

impl TryFrom<StatusList> for EncodedStatusList {
    type Error = OAuthTSLError;

    fn try_from(status_list: StatusList) -> Result<Self, Self::Error> {
        let encoded_list = status_list.compress_encode()?;
        Ok(EncodedStatusList {
            status_size: status_list.status_size.as_u8(),
            status_list: encoded_list,
            aggregation_uri: status_list.aggregation_uri,
        })
    }
}

impl EncodedStatusList {
    pub fn new(status_size: Bits, status_list: String, aggregation_uri: Option<String>) -> Self {
        EncodedStatusList {
            status_size: status_size.as_u8(),
            status_list,
            aggregation_uri,
        }
    }

    pub fn decode_decompress(&self) -> Result<Vec<u8>, OAuthTSLError> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&self.status_list)?;
        let mut d = ZlibDecoder::new(&bytes[..]);
        let mut out = Vec::new();
        d.read_to_end(&mut out)?;

        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusList {
    #[serde(rename = "bits")]
    pub status_size: Bits,
    #[serde(rename = "lst")]
    pub status_list: Vec<u8>,
    // todo: not implemented yet
    pub aggregation_uri: Option<String>,
}

/// The default Status Size is 1 bit (VALID or INVALID) and no Aggregation Uri.
/// The default length of the status list is 50 bytes, 400 bits.
/// This is the recommended minimum size for a status list so to encourage "herd privacy" within a Status List.
impl Default for StatusList {
    fn default() -> Self {
        StatusList {
            status_size: Bits::One,
            status_list: vec![0u8; 50],
            aggregation_uri: None,
        }
    }
}

impl TryFrom<EncodedStatusList> for StatusList {
    type Error = OAuthTSLError;

    fn try_from(encoded_list: EncodedStatusList) -> Result<Self, Self::Error> {
        let status_list = encoded_list.decode_decompress()?;
        Ok(StatusList {
            status_size: Bits::try_from(encoded_list.status_size)?,
            status_list,
            aggregation_uri: encoded_list.aggregation_uri,
        })
    }
}

impl StatusList {
    pub fn get_index(&self, index: usize) -> Result<u8, OAuthTSLError> {
        let status_list_len = self.status_list.len() * (8 / self.status_size.as_usize());
        if index >= status_list_len {
            return Err(OAuthTSLError::IndexNotFound(index));
        }

        let byte = self.status_list[index * self.status_size.as_usize() / 8];
        let bit_index = (index * self.status_size.as_usize()) % 8;
        match self.status_size {
            Bits::One => {
                let mask = 0b1 << bit_index;
                Ok((byte & mask) >> bit_index)
            }
            Bits::Two => {
                let mask = 0b11 << bit_index;
                Ok((byte & mask) >> bit_index)
            }
            Bits::Four => {
                let mask = 0b1111 << bit_index;
                Ok((byte & mask) >> bit_index)
            }
            Bits::Eight => {
                let mask = 0b11111111 << bit_index;
                Ok((byte & mask) >> bit_index)
            }
        }
    }

    /// Sets the status at the specified index to the given value.
    /// Always enlarges the status list to the required size if it is not already large enough.
    /// Therefore an index can never be out of bounds.
    pub fn set_index(&mut self, index: usize, value: u8) -> Result<(), OAuthTSLError> {
        if value as u16 >= (1 << self.status_size.as_u8()) {
            return Err(OAuthTSLError::InvalidStatusType(value));
        }

        let status_list_len = self.status_list.len() * (8 / self.status_size.as_usize());
        if index >= status_list_len {
            self.status_list
                .resize(index * (8 / self.status_size.as_usize()) + 1, 0);
        }

        let mut byte = self.status_list[index * self.status_size.as_usize() / 8];
        let bit_index = (index * self.status_size.as_usize()) % 8;

        let mask = match self.status_size {
            Bits::One => 0b1 << bit_index,
            Bits::Two => 0b11 << bit_index,
            Bits::Four => 0b1111 << bit_index,
            Bits::Eight => 0b11111111 << bit_index,
        };

        // Clear the bits at the specified position
        byte &= !mask;
        // Set the bits to the new value
        byte |= (value << bit_index) & mask;

        self.status_list[index * self.status_size.as_usize() / 8] = byte;

        Ok(())
    }

    /// Uses an enum to allow single or multiple input values, enabling setting all indices to one value or setting a value per index.
    pub fn set_index_array(
        &mut self,
        indices: Vec<usize>,
        index_input: IndexInput,
    ) -> Result<(), OAuthTSLError> {
        match index_input {
            IndexInput::Single(value) => {
                for &index in &indices {
                    self.set_index(index, value)?;
                }
            }
            IndexInput::Multiple(values) => {
                if indices.len() != values.len() {
                    return Err(OAuthTSLError::InvalidIndicesValuesPair);
                }
                for (i, &index) in indices.iter().enumerate() {
                    self.set_index(index, values[i])?;
                }
            }
        }
        Ok(())
    }

    /// Compress the status list using DEFLATE [RFC1951] and ZLIB [RFC1950] data format, using the highest compression.
    /// Then it encodes the compressed status list in base64 URL-safe, no padding.
    /// Returns the output as a String
    pub fn compress_encode(&self) -> Result<String, OAuthTSLError> {
        let mut compressor = ZlibEncoder::new(Vec::new(), Compression::best());
        compressor.write_all(&self.status_list)?;
        let compressed = compressor.finish()?;
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(compressed);

        Ok(encoded)
    }
}

// TODO: support adding custom status types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS, Default)]
pub enum StatusType {
    #[default]
    VALID = 0,
    INVALID = 1,
    SUSPENDED = 2,
    // The Status Type value 0x03 and Status Type values in the range 0x0B
    // until 0x0F are permanently reserved as application specific.
    // Meaning free for the implementer to implement.
    UNDEFINED,
    // All other Status Type values are reserved for future registration.
    RESERVED,
}

impl TryFrom<u8> for StatusType {
    type Error = OAuthTSLError;

    fn try_from(value: u8) -> Result<Self, OAuthTSLError> {
        match value {
            0 => Ok(StatusType::VALID),
            1 => Ok(StatusType::INVALID),
            2 => Ok(StatusType::SUSPENDED),
            3 | 11..=15 => Ok(StatusType::UNDEFINED), // Application specific
            _ => Err(OAuthTSLError::InvalidStatusType(value)),
        }
    }
}

impl TryInto<u8> for StatusType {
    type Error = OAuthTSLError;

    fn try_into(self) -> Result<u8, Self::Error> {
        match self {
            StatusType::VALID => Ok(0),
            StatusType::INVALID => Ok(1),
            StatusType::SUSPENDED => Ok(2),
            StatusType::UNDEFINED => Ok(3), // Application specific
            _ => Err(OAuthTSLError::InvalidStatusType(self as u8)),
        }
    }
}

// Helpers
#[derive(Debug, Clone)]
pub enum IndexInput {
    Single(u8),
    Multiple(Vec<u8>),
}

#[cfg(test)]
mod test {
    use super::*;

    /// Example 1 from appendix "Test vectors for Status List encoding" of the specification.
    /// This fn tests 3 functions; set_index, get_index, compress_encode
    #[test]
    pub fn test_compress_example_1() {
        let mut status_list = StatusList {
            status_size: Bits::One,
            status_list: vec![0u8; 131072],
            ..Default::default()
        };

        // I did not use fn set_index_array here to mimic the example from the spec as much as possible.
        status_list.set_index(0, 1).unwrap();
        status_list.set_index(1993, 1).unwrap();
        status_list.set_index(25460, 1).unwrap();
        status_list.set_index(159495, 1).unwrap();
        status_list.set_index(495669, 1).unwrap();
        status_list.set_index(554353, 1).unwrap();
        status_list.set_index(645645, 1).unwrap();
        status_list.set_index(723232, 1).unwrap();
        status_list.set_index(854545, 1).unwrap();
        status_list.set_index(934534, 1).unwrap();
        status_list.set_index(1000345, 1).unwrap();

        assert_eq!(status_list.get_index(1000345).unwrap(), 1);

        assert_eq!(status_list.compress_encode().unwrap(), "eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogEAAKkeCQAAAAAAAAAAAAAAAAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAAA7KpLAAAAAAAAAAAAAAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAAAACAZC8L2AEb");
    }

    /// Example 2 from appendix "Test vectors for Status List encoding" of the specification.
    /// This fn tests 3 functions; set_index, get_index, compress_encode
    #[test]
    pub fn test_compress_example_2() {
        let mut status_list = StatusList {
            status_size: Bits::Two,
            status_list: vec![0u8; 131072 * 2],
            ..Default::default()
        };

        // I did not use fn set_index_array here to mimic the example from the spec as much as possible.
        status_list.set_index(0, 1).unwrap();
        status_list.set_index(1993, 2).unwrap();
        status_list.set_index(25460, 1).unwrap();
        status_list.set_index(159495, 3).unwrap();
        status_list.set_index(495669, 1).unwrap();
        status_list.set_index(554353, 1).unwrap();
        status_list.set_index(645645, 2).unwrap();
        status_list.set_index(723232, 1).unwrap();
        status_list.set_index(854545, 1).unwrap();
        status_list.set_index(934534, 2).unwrap();
        status_list.set_index(1000345, 3).unwrap();

        assert_eq!(status_list.get_index(1000345).unwrap(), 3);

        assert_eq!(status_list.compress_encode().unwrap(), "eNrt2zENACEQAEEuoaBABP5VIO01fCjIHTMStt9ovGVIAAAAAABAbiEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEB5WwIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAID0ugQAAAAAAAAAAAAAAAAAQG12SgAAAAAAAAAAAAAAAAAAAAAAAAAAAOCSIQEAAAAAAAAAAAAAAAAAAAAAAAD8ExIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwJEuAQAAAAAAAAAAAAAAAAAAAAAAAMB9SwIAAAAAAAAAAAAAAAAAAACoYUoAAAAAAAAAAAAAAEBqH81gAQw");
    }

    /// Example 3 from appendix "Test vectors for Status List encoding" of the specification.
    /// This fn tests 3 functions; set_index, get_index, compress_encode
    #[test]
    pub fn test_compress_example_3() {
        let mut status_list = StatusList {
            status_size: Bits::Four,
            status_list: vec![0u8; 131072 * 4],
            ..Default::default()
        };

        // I did not use fn set_index_array here to mimic the example from the spec as much as possible.
        status_list.set_index(0, 1).unwrap();
        status_list.set_index(1993, 2).unwrap();
        status_list.set_index(35460, 3).unwrap();
        status_list.set_index(459495, 4).unwrap();
        status_list.set_index(595669, 5).unwrap();
        status_list.set_index(754353, 6).unwrap();
        status_list.set_index(845645, 7).unwrap();
        status_list.set_index(923232, 8).unwrap();
        status_list.set_index(924445, 9).unwrap();
        status_list.set_index(934534, 10).unwrap();
        status_list.set_index(1000345, 12).unwrap();
        status_list.set_index(1004534, 11).unwrap();
        status_list.set_index(1030203, 13).unwrap();
        status_list.set_index(1030204, 14).unwrap();
        status_list.set_index(1030205, 15).unwrap();

        assert_eq!(status_list.get_index(1030205).unwrap(), 15);

        assert_eq!(status_list.compress_encode().unwrap(), "eNrt0EENgDAQADAIHwImkIIEJEwCUpCEBBQRHOy35Li1EjoOQGabAgAAAAAAAAAAAAAAAAAAACC1SQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABADrsCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADoxaEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIIoCgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACArpwKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGhqVkAzlwIAAAAAiGVRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABx3AoAgLpVAQAAAAAAAAAAAAAAwM89rwMAAAAAAAAAAAjsA9xMBMA");
    }

    /// Example 4 from appendix "Test vectors for Status List encoding" of the specification.
    /// This fn tests 3 functions; set_index, get_index, compress_encode
    #[test]
    pub fn test_compress_example_4() {
        let mut status_list = StatusList {
            status_size: Bits::Eight,
            status_list: vec![0u8; 131072 * 8],
            ..Default::default()
        };

        let indices = vec![
            233478, 52451, 576778, 513575, 468106, 292632, 214947, 182323, 884834, 66653, 62489,
            196493, 458517, 487925, 55649, 416992, 879796, 462297, 942059, 583408, 13628, 334829,
            886286, 713557, 582738, 326064, 451545, 705889, 214350, 194502, 796765, 202828, 752834,
            721327, 554740, 91122, 963483, 261779, 793844, 165255, 614839, 758403, 403258, 145867,
            96100, 477937, 606890, 167335, 488197, 211815, 797182, 582952, 950870, 765108, 341110,
            776325, 745056, 439368, 559893, 149741, 358903, 513405, 342679, 969429, 795775, 566121,
            460566, 680070, 117310, 480348, 67319, 661552, 841303, 561493, 138807, 442463, 659927,
            445910, 1046963, 829700, 962282, 299623, 555493, 292826, 517215, 551009, 898490,
            837603, 759161, 459948, 290102, 1034977, 190650, 98810, 229950, 320531, 335506, 885333,
            133227, 806915, 800313, 981571, 527253, 24077, 240232, 559572, 713399, 233941, 615514,
            911768, 331680, 951527, 6805, 552366, 374660, 223159, 625884, 417146, 320527, 784154,
            338792, 1199, 679804, 1024680, 40845, 234603, 761225, 644903, 502167, 121477, 505144,
            165165, 179628, 1019195, 145149, 263738, 269256, 996739, 346296, 555864, 887384,
            444173, 421844, 653716, 836747, 783119, 918762, 946835, 253764, 519895, 471224, 134272,
            709016, 44112, 482585, 461829, 15080, 148883, 123467, 480125, 141348, 65877, 692958,
            148598, 499131, 584009, 1017987, 449287, 277478, 991262, 509602, 991896, 853666,
            399318, 197815, 203278, 903979, 743015, 888308, 862143, 979421, 113605, 206397, 127113,
            844358, 711569, 229153, 521470, 401793, 398896, 940810, 293983, 884749, 384802, 584151,
            970201, 523882, 158093, 929312, 205329, 106091, 30949, 195586, 495723, 348779, 852312,
            1018463, 1009481, 448260, 841042, 122967, 345269, 794764, 4520, 818773, 556171, 954221,
            598210, 887110, 1020623, 324632, 398244, 622241, 456551, 122648, 127837, 657676,
            119884, 105156, 999897, 330160, 119285, 168005, 389703, 143699, 142524, 493258, 846778,
            251420, 516351, 83344, 171931, 879178, 663475, 546865, 428362, 658891, 500560, 557034,
            830023, 274471, 629139, 958869, 663071, 152133, 19535,
        ];

        let values: Vec<u8> = (0..indices.len()).map(|i| i as u8).collect();

        status_list
            .set_index_array(indices, IndexInput::Multiple(values))
            .unwrap();

        assert_eq!(status_list.get_index(19535).unwrap(), 255);

        assert_eq!(status_list.compress_encode().unwrap(), "eNrt0WOQM2kYhtGsbdu2bdu2bdu2bdu2bdu2jVnU1my-SWYm6U5enFPVf7ue97orFYAo7CQBAACQuuckAABStqUEAAAAAAAAtN6wEgAE71QJAAAAAIrwhwQAAAAAAdtAAgAAAAAAACLwkAQAAAAAAAAAAACUaFcJAACAeJwkAQAAAAAAAABQvL4kAAAAWmJwCQAAAAAAAAjAwBIAAAB06ywJoDKQBARpfgkAAAAAAAAAAAAAAAAAAACo50sJAAAAAAAAAOiRcSQAAAAAgAJNKgEAAG23mgQAAAAAAECw3pUAQvegBAAAAAAAAADduE4CAAAAyjSvBAAQiw8koHjvSABAb-wlARCONyVoxtMSZOd0CQAAAOjWDRKQmLckAAAAAACysLYEQGcnSAAAAAAQooUlAABI15kSAIH5RAIgLB9LABC4_SUgGZNIAABAmM6RoLbTJIASzCIBAEAhfpcAAAAAAABquk8CAAAAAAAAaJl9SvvzBOICAFWmkIBgfSgBAAAANOgrCQAAAAAAAADStK8EAAC03gASAAAAAAAAAADFWFUCAAAAMjOaBEADHpYAQjCIBADduFwCAAAAAGitMSSI3BUSAECOHpAA6IHrJQAAAAAAsjeVBAAAKRpVAorWvwQAAAAAAAAAkKRtJAAAAAAAgCbcLAF0bXUJAAAAoF02kYDg7CYBAAAAAEB6NpQAAAAAAAAAAAAAAEr1uQQAAF06VgIAAAAAAAAAqDaeBAAQqgMkAAAAAABogQMlAAAAAAAa87MEAAAQiwslAAAAAAAAAAAAAAAAMrOyBAAAiekv-hcsY0Sgne6QAAAAAAAgaUtJAAAAAAAAAAAAAAAAAAAAAAAAAADwt-07vjVkAAAAgDy8KgFAUEaSAAAAAJL3vgQAWdhcAgAAoBHDSUDo1pQAAACI2o4SAABZm14CALoyuwQAAPznGQkgZwdLAAAQukclAAAAAAAAAAAAgKbMKgEAAAAAAAAAAAAAAAAAAECftpYAAAAAAAAAAAAACnaXBAAAAADk7iMJAAAAAAAAAABqe00CAnGbBBG4TAIAgFDdKgFAXCaWAAAAAAAAAAAAAAAAAKAJQwR72XbGAQAAAKAhh0sAAAAAAABQgO8kAAAAAAAAAAAAACAaM0kAAAC5W0QCAIJ3mAQAxGwxCQAA6nhSAsjZBRIAANEbWQIAAAAAaJE3JACAwA0qAUBIVpKAlphbAiAPp0iQnKEkAAAAAAAgBP1KAAAAdOl4CQAAAAAAAPjLZBIAAG10RtrPm8_CAEBMTpYAAAAAAIjQYBL8z5QSAAAAAEDYPpUAACAsj0gAAADQkHMlAAjHDxIA0Lg9JQAAgHDsLQEAAABAQS6WAAAAgLjNFs2l_RgLAIAEfCEBlGZZCQAAaIHjJACgtlskAAAozb0SAAAAVFtfAgAAAAAAAAAAAAAAAAAAAAAAAKDDtxIAAAAAVZaTAKB5W0kAANCAsSUgJ0tL0GqHSNBbL0gAZflRAgCARG0kQXNmlgCABiwkAQAAAEB25pIAAAAAAAAAAAAAoFh9SwAAAAAAADWNmOSrpjFsEoaRgDKcF9Q1dxsEAAAAAAAAAAAAAAAAgPZ6SQIAAAAAAAAAgChMLgEAAAAAAAAAqZlQAsK2qQQAAAAAAAD06XUJAAAAqG9bCQAAgLD9IgEAAAAAAAAAAAAAAAAAAEBNe0gAAAAAAAAAAEBPHSEBAAAAlOZtCYA4fS8B0GFRCQAo0gISAOTgNwmC840EAAAAAAAAAAAAAAAAAAAAUJydJfjXPBIAAAAAAAAAAAAAAABk6WwJAAAAAAAAAAAAAAAAqG8UCQAAgPpOlAAAIA83SQAANWwc9HUjGAgAAAAAAACAusaSAAAAAAAAAAAAAAAAAAAAAAAAAAAAqHKVBACQjxklAAAAAAAAAKBHxpQAAAAAACBME0lAdlaUAACyt7sEAAAA0Nl0EgAAAAAAAAAAAABA-8wgAQAAAAAAAKU4SgKgUtlBAgAAAAAAAAAAgMCMLwEE51kJICdzSgCJGl2CsE0tAQAA0L11JQAAAAAAAAjUOhIAAAAAAAAAAAAAAGTqeQkAAAAAAAAAAAAAKM8SEjTrJwkAAAAAAACocqQEULgVJAAAACjDUxJUKgtKAAAAqbpRAgCA0n0mAQAAAABAGzwmAUCTLpUAAAAAAAAAAEjZNRIAAAAAAAAAAAAAAAAAAAAA8I-vJaAlhpQAAAAAAHrvzjJ-OqCuuVlLAojP8BJAr70sQZVDJYAgXS0BAAAAAAAAAAAAtMnyEgAAAAAAFONKCQAAAAAAAADorc0kAAAAAAAAgDqOlgAAAAAAAAAAAADIwv0SAAAAAAAAAAAAAADBuV0CIFVDSwAAAABAAI6RAAAAAGIwrQSEZAsJAABouRclAAAAAKDDrxIAAAA0bkkJgFiMKwEAAAAAAHQyhwRk7h4JAAAAAAAAAAAgatdKAACUYj0JAAAAAAAAAAAAQnORBLTFJRIAAAAAkIaDJAAAAJryngQAAAAAAAAAAAA98oQEAAAAAAAAAEC2zpcgWY9LQKL2kwAgGK9IAAAAAPHaRQIAAAAAAAAAAADIxyoSAAAAAAAAAAAAAADQFotLAECz_gQ1PX-B")
    }
}
