from struct import unpack as up
import sys, os, hashlib

# Originally written by SciresM.
# Modified by yellows8 for PFS0 support, and for dir-creation.

dirs, files = None, None

def read_at(fp, off, len):
    fp.seek(off)
    return fp.read(len)

def read_u8(fp, off):
    return up('<B', read_at(fp, off, 1))[0]

def read_u16(fp, off):
    return up('<H', read_at(fp, off, 2))[0]

def read_u32(fp, off):
    return up('<I', read_at(fp, off, 4))[0]

def read_u64(fp, off):
    return up('<Q', read_at(fp, off, 8))[0]

def read_filename(fp, off, l):
    if l == 0:
        return ''
    s = read_at(fp, off, l)
    if b'\0' in s:
        s = s[:s.index(b'\0')]
    return s

def dump_file(name, offset, size, hsh_sz, hsh, fs_type):
    global archive, out_dir
    path = os.path.join(out_dir, name.decode('utf-8') if isinstance(name, bytes) else name)
    print('Dumping %s (%012X-%012X) to %s...' % (name, offset, offset+size, path))
    archive.seek(offset)
    if fs_type==0 and hashlib.sha256(archive.read(hsh_sz)).digest() != hsh:
        print('Warning: Hash is invalid for %s!' % (name))
    archive.seek(offset)
    with open(path, 'wb') as f:
        ofs = 0
        sz = 0x800000
        while ofs < size:
            if size - ofs < sz:
                sz = size - ofs
            f.write(archive.read(sz))
            ofs += sz
    print('Dumped!')


def main(argc, argv):
    fs_type = 0
    if argc != 3:
        print('Usage: %s in_file out_dir' % argv[0])
        return
    global archive, dirs_off, files_off, fdata_off
    try:
        archive = open(argv[1], 'rb')
        magicnum = read_at(archive, 0, 4)
        if magicnum != b'HFS0':
            fs_type = 1
            if magicnum != b'PFS0':
                print('Error: Invalid archive.')
                return
    except:
        print('Failed to open %s.' % argv[1])
        return

    global out_dir
    out_dir = argv[2]

    if os.path.exists(out_dir) == False:
        os.mkdir(out_dir)

    entrysize = 0x40
    if fs_type==1:
        entrysize = 0x18

    magic, num_files, name_table_size, reserved = up('<IIII', read_at(archive, 0, 0x10))

    name_table = read_at(archive, 0x10 + entrysize * num_files, name_table_size)

    archive.seek(0x10)

    files = []
    for i in range(num_files):
        f_meta = archive.read(entrysize)
        if fs_type==0:
            offset, size, string_ofs, hsh_sz, unk2, unk3, hsh  = up('<QQIIII32s', f_meta)
        if fs_type==1:
            offset, size, string_ofs, unk2  = up('<QQII', f_meta)
            hsh_sz = 0
            hsh = b''
        name = name_table[string_ofs:]
        if b'\x00' in name:
            name = name[:name.index(b'\x00')]
        files.append((0x10 + entrysize * num_files + name_table_size + offset, size, name, hsh_sz, hsh))


    for file in files:
        offset, size, name, hsh_sz, hsh = file
        dump_file(name, offset, size, hsh_sz, hsh, fs_type)



if __name__ == '__main__':
    main(len(sys.argv), sys.argv)