use crate::proxy::buffer_pool::PooledBytes;

pub struct MessageReader {
    buf: PooledBytes,
    pos: usize,
}

impl MessageReader {
    pub fn new(buf: PooledBytes) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn read_byte(&mut self) -> Result<u8, Box<dyn std::error::Error>> {
        if self.remaining() <= 0 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Message body is empty",
            )));
        }

        let byte = self.buf[self.pos];

        self.pos += 1;

        Ok(byte)
    }

    pub fn read_u16(&mut self) -> Result<u16, Box<dyn std::error::Error>> {
        if self.remaining() < 2 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Not enough bytes to read",
            )));
        }

        let value = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);

        self.pos += 2;

        Ok(value)
    }

    pub fn read_u32(&mut self) -> Result<u32, Box<dyn std::error::Error>> {
        if self.remaining() < 4 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Not enough bytes to read",
            )));
        }

        let value = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);

        self.pos += 4;

        Ok(value)
    }
}
