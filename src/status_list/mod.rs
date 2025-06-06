pub mod status_types;

#[derive(Debug, Clone)]
pub struct StatusList {
    pub status_size: Bits,
    pub status_list: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum Bits {
    One = 1,
    Two = 2,
    Four = 4,
    Eight = 8,
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

impl StatusList {
    pub fn get_index(&self, index: usize) -> Result<u8, String> {
        let status_list_len = self.status_list.len() * (8 / self.status_size.as_usize());
        if index >=  status_list_len {
            return Err(format!("Index {} out of bounds for status list of size {}", index, status_list_len));
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
}