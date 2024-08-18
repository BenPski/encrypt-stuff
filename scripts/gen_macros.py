#!/usr/bin/env python3
def aes():
    sizes = ["128", "256"]
    styles = ["", "Siv"]
    for size in sizes:
        for style in styles:
            name = f"Aes{size}Gcm{style}"
            if style == "":
                path = f"aes_gcm::{name}"
            else:
                path = f"aes_gcm_siv::{name}"
            yield (name, path)

def chacha():
    sizes = ["8", "12", "20"]
    styles = ["", "X"]
    for size in sizes:
        for style in styles:
            name = f"{style}ChaCha{size}Poly1305"
            path = f"chacha20poly1305::{name}"
            yield (name, path)

def macro(name, path, serial):
    serial_path = f"crate::serialization::{serial.lower()}::{serial}"
    return f'#[cfg(all(feature = "{name.lower()}", feature = "{serial.lower()}"))]\ncipher!({name}{serial}, {path}, {serial_path});'

def main():
    serials = ["Bitcode", "Bincode"]
    for serial in serials:
        for (name, path) in aes():
            print(macro(name, path, serial))
        for (name, path) in chacha():
            print(macro(name, path, serial))




# because whatever
if __name__ == "__main__":
    main()
