def get_tweak(self, sector):
    '''Gets tweak for use in XEX.'''
    tweak = 0
    for i in xrange(0x10): # 0x10 = block_size
        tweak |= (sector & 0xFF) << ((0x10 - i - 1) * 8)
        sector >>= 8
    return tweak
  
def get_nintendo_tweak(self, sector):
    '''Gets Nintendo tweak for use in XEX.'''
    tweak = 0
    for i in xrange(0x10): # 0x10 = block_size
        tweak |= (sector & 0xFF) << (i * 8)
        sector >>= 8
    return tweak

def tweak_to_block(tweak):
    return ('%032X' % tweak).decode('hex')