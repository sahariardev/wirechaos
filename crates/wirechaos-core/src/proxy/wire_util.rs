pub fn put_cstr(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(value.as_bytes());
    buf.push(b'\0');
}