
import subprocess

class AwesomeDecrypt:
  
  def __init__(self):
    self.keys = {}
    
  def add_key(self, frame, key):
    self.keys[key] = frame

  def getkeystream(self, key, frame, nbits):
      key = "%.16x"%key
      subby = subprocess.Popen([ './keygen', key, str(frame), str(nbits) ], stdout = subprocess.PIPE);
      keystream, _ = subby.communicate()
      return [ ord(x) & 1 for x in keystream.rstrip() ]

  def xorstream(self, a, b):
      return map(lambda x, y: x ^ y, a, b)

  def modfn(self, frame):
      t1 = frame / 1326
      t2 = frame % 26
      t3 = frame % 51
      return (t1 << 11) | (t3 << 5) | t2

  def parse_reverse_key(self, s):
  	parts = s.split()[::-1]
  	x = int("0x"+"".join(parts),16)
  	return x
  
  def bits2bytes(self, bits):
    bytes = ""
    if len(bits) % 8:
      raise Exception("wrong bitstream size")
    for i in range(0, len(bits), 8):
      piece = bits[i:i+8]
      byte = chr(int(piece, 2))
      bytes += byte
    return bytes
    

  def decrypt(self, ciphertext, start_fn):
    """
    takes ciphertext in as a string of 0s and 1s
    returns a string of 0s and 1s
    """
    #try each known key?
    if len(ciphertext) % 114:
      raise "Wrong Length for ciphertext"
    
    ret = ""
    for key in self.keys:
      for i in range(0, len(ciphertext), 114):
        fn = start_fn + i / 114
        frame = self.modfn(fn)
        
        #print "%.16x"%key, fn
        keystream = self.getkeystream(key, frame, 114*2)
        keystream = keystream[:114] #assuem downlink
        block = [int(x) for x in ciphertext[i:i+114]]
        
        decrypted = self.xorstream(keystream, block)
        decrypted = "".join([chr(x+0x30) for x in decrypted])
        ret += decrypted

    return ret

  def outerleave(self, bitstream):
    #TODO -> bother writing the inverse function...
    lookup = [0, 212, 310, 408, 51, 149, 247, 345, 100, 198, 296, 394, 37, 135, 233, 445, 86, 184, 282, 380, 23, 121, 333, 431, 72, 170, 268, 366, 9, 221, 319, 417, 58, 156, 254, 352, 109, 207, 305, 403, 44, 142, 240, 452, 95, 193, 291, 389, 30, 128, 340, 438, 81, 179, 277, 375, 16, 114, 326, 424, 67, 165, 263, 361, 2, 214, 312, 410, 53, 151, 249, 347, 102, 200, 298, 396, 39, 137, 235, 447, 88, 186, 284, 382, 25, 123, 335, 433, 74, 172, 270, 368, 11, 223, 321, 419, 60, 158, 256, 354, 111, 209, 307, 405, 46, 144, 242, 454, 97, 195, 293, 391, 32, 130, 228, 440, 83, 181, 279, 377, 18, 116, 328, 426, 69, 167, 265, 363, 4, 216, 314, 412, 55, 153, 251, 349, 104, 202, 300, 398, 41, 139, 237, 449, 90, 188, 286, 384, 27, 125, 337, 435, 76, 174, 272, 370, 13, 225, 323, 421, 62, 160, 258, 356, 113, 211, 309, 407, 48, 146, 244, 342, 99, 197, 295, 393, 34, 132, 230, 442, 85, 183, 281, 379, 20, 118, 330, 428, 71, 169, 267, 365, 6, 218, 316, 414, 57, 155, 253, 351, 106, 204, 302, 400, 43, 141, 239, 451, 92, 190, 288, 386, 29, 127, 339, 437, 78, 176, 274, 372, 15, 227, 325, 423, 64, 162, 260, 358, 1, 213, 311, 409, 50, 148, 246, 344, 101, 199, 297, 395, 36, 134, 232, 444, 87, 185, 283, 381, 22, 120, 332, 430, 73, 171, 269, 367, 8, 220, 318, 416, 59, 157, 255, 353, 108, 206, 304, 402, 45, 143, 241, 453, 94, 192, 290, 388, 31, 129, 341, 439, 80, 178, 276, 374, 17, 115, 327, 425, 66, 164, 262, 360, 3, 215, 313, 411, 52, 150, 248, 346, 103, 201, 299, 397, 38, 136, 234, 446, 89, 187, 285, 383, 24, 122, 334, 432, 75, 173, 271, 369, 10, 222, 320, 418, 61, 159, 257, 355, 110, 208, 306, 404, 47, 145, 243, 455, 96, 194, 292, 390, 33, 131, 229, 441, 82, 180, 278, 376, 19, 117, 329, 427, 68, 166, 264, 362, 5, 217, 315, 413, 54, 152, 250, 348, 105, 203, 301, 399, 40, 138, 236, 448, 91, 189, 287, 385, 26, 124, 336, 434, 77, 175, 273, 371, 12, 224, 322, 420, 63, 161, 259, 357, 112, 210, 308, 406, 49, 147, 245, 343, 98, 196, 294, 392, 35, 133, 231, 443, 84, 182, 280, 378, 21, 119, 331, 429, 70, 168, 266, 364, 7, 219, 317, 415, 56, 154, 252, 350, 107, 205, 303, 401, 42, 140, 238, 450, 93, 191, 289, 387, 28, 126, 338, 436, 79, 177, 275, 373, 14, 226, 324, 422, 65, 163, 261, 359]
    bitstream = list(bitstream)
    o = ["0"]*456
    if len(bitstream) != 456:
      raise Exception("Cant outerleave, wrong bitstream size: %d"%len(bitstream))
    for i in range(0, len(bitstream)): #MUST BE 456
    	o[ lookup[i] ] = bitstream[i]
    return "".join(o)
  
  def unconvolute(self, bitstream):
    if len(bitstream) != 456:
      raise Exception("Cant unconvolute, wrong bitstream size: %d"%len(bitstream))
    subby = subprocess.Popen([ './unconvolute', bitstream], stdout = subprocess.PIPE);
    result, _ = subby.communicate()
    return "".join(result.split())
    
  
if __name__ == '__main__':

  ciphertext = "011110111011111111101111110100010111111011110001111001000110001100001101011101011111010001100000001111010011101001101000110111100111011011101100010000111001101011101001000010000100101111100111111101100111001100110111010111011001110010101110110001100100111110110110111101001011010010101010001110000011000000011111011000011100010011100101000100010000110111111010000100100010110011101110100110100001100101011111100111010000001101101101101101111111010011010110"
  plaintext  = "101000011001000101111010011011101001010011110101011101010110001001000101111110000000110010100010001011110111100100000011011001011111001101100100100011111010110111110001011010100111110101111101100010110010100110101111110000010011100010010001100100010000011110011100001111011111010100110001010000101101010101011000001011100001101111101000111110011001001001100001101011100100010101111000111010100010011111110000111010010010011011110100011100001000001100111011"
  
  x = AwesomeDecrypt()
  
  start_fn = 1735566
  count = 0
  for i in range(0, len(ciphertext), 114):
    fn = start_fn + count
    frame =  x.modfn(fn)    
    keystream = x.getkeystream( x.parse_reverse_key("12 00 cf 3c df e8 0c 00") , frame, 114*2)
    keystream = keystream[:114]
    block = [int(z) for z in ciphertext[i:i+114]]
    decrypted = x.xorstream(keystream, block)
    decrypted = "".join([chr(z+0x30) for z in decrypted])
    if decrypted not in plaintext:
      print 'wut``'
    print fn, decrypted
    count += 1

