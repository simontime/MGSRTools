#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// reverses a byte using bit magic
#define REVERSE_BYTE(b) ((uint8_t)((((b) * 0x80200802ULL) & 0x0884422110ULL) * 0x0101010101ULL >> 32))

// get filesize
size_t fsize(FILE *f)
{
    size_t sz;
    
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    rewind(f);
    
    return sz;
}

int main(int argc, char **argv)
{
    char     filename[FILENAME_MAX];
    FILE    *f_in, *f_out;
    uint8_t *buf, *buf_start, *search_end;
    uint8_t  key[0x10];
    uint32_t bfstm_size, i, num;
    size_t   total_size;
    
    // attempt to open 42
    if ((f_in = fopen("42", "rb")) == NULL)
    {
        perror("Error opening 42");
        return 1;
    }
    
    // get total size and allocate buf
    total_size = fsize(f_in); 
    buf = buf_start = malloc(total_size);
    
    // read entire archive (this is not good practice)
    fread(buf, 1, total_size, f_in);
    fclose(f_in);
    
    // search end is end of buf - 0x58 just so we don't go over the buffer when checking stuff
    search_end = buf + total_size - 0x58;
    
    for (num = 0; buf < search_end; buf += 0x20)
    {
        // check magic against known plaintext key bytes
        if (REVERSE_BYTE(buf[0] ^ buf[0x50])        == 'F'  &&
            REVERSE_BYTE(buf[1] ^ buf[0x51])        == 'S'  &&
            REVERSE_BYTE(buf[2] ^ buf[0x52])        == 'T'  &&
            REVERSE_BYTE(buf[3] ^ buf[0x53])        == 'M'  &&
            REVERSE_BYTE(buf[4] ^ buf[0x54] ^ 0xff) == 0xff &&
            REVERSE_BYTE(buf[5] ^ buf[0x55] ^ 0xff) == 0xfe &&
            REVERSE_BYTE(buf[6] ^ buf[0x56] ^ 0xff) == 0x40 &&
            REVERSE_BYTE(buf[7] ^ buf[0x57] ^ 0xff) == 0x00)
        {
            // generate filename
            sprintf(filename, "%03d.bfstm", num++);
            
            // open file
            f_out = fopen(filename, "wb");
            
            // extract key bytes from known plaintext
            memcpy(&key[0], &buf[0x50], 4);
            key[4] = buf[0x54] ^ 0xff;
            key[5] = buf[0x55] ^ 0xff;
            key[6] = buf[0x56] ^ 0xff;
            key[7] = buf[0x57] ^ 0xff;
            memcpy(&key[8], &buf[0x38], 8);
            
            // extract u32 size
            bfstm_size  = REVERSE_BYTE(buf[15] ^ key[15]);
            bfstm_size <<= 8;
            bfstm_size |= REVERSE_BYTE(buf[14] ^ key[14]);
            bfstm_size <<= 8;
            bfstm_size |= REVERSE_BYTE(buf[13] ^ key[13]);
            bfstm_size <<= 8;
            bfstm_size |= REVERSE_BYTE(buf[12] ^ key[12]);
            
            // print info
            printf("Found BFSTM - Offset: 0x%08lx, Size: 0x%08x, Key: ", buf - buf_start, bfstm_size);
            
            for (i = 0; i < sizeof(key); i++)
                printf("%02x", key[i]);
            
            putchar('\n');
            
            // decrypt by xoring the byte with the key byte and reversing the bits
            for (i = 0; i < bfstm_size; i++)
                *buf++ = REVERSE_BYTE(*buf ^ key[i % sizeof(key)]);
            
            // write file
            fwrite(buf - bfstm_size, 1, bfstm_size, f_out);
            fclose(f_out);
        }
    }
    
    free(buf_start);
    
    puts("Done!");
    
    return 0;
}
