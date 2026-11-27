/* Thin memory adapter for the separately supplied libmspack LZX decoder.
 * The decoder itself remains separately licensed and is not bundled here.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "mspack.h"
#include "lzx.h"
struct buffer { unsigned char *p; size_t size, pos; };
static int read_buffer(struct mspack_file *f, void *dst, int n) {
    struct buffer *b=(struct buffer*)f;
    if(n<0) return -1;
    size_t k=(size_t)n; if(k>b->size-b->pos) k=b->size-b->pos;
    memcpy(dst,b->p+b->pos,k); b->pos+=k; return (int)k;
}
static int write_buffer(struct mspack_file *f, void *src, int n) {
    struct buffer *b=(struct buffer*)f;
    if(n<0 || (size_t)n>b->size-b->pos) return -1;
    memcpy(b->p+b->pos,src,(size_t)n); b->pos+=(size_t)n; return n;
}
static void *alloc_buffer(struct mspack_system *s,size_t n) { (void)s; return calloc(1,n); }
static void copy_buffer(void *src,void *dst,size_t n) { memcpy(dst,src,n); }
static void message(struct mspack_file *f,const char *fmt,...) {(void)f;(void)fmt;}
#ifdef _WIN32
__declspec(dllexport)
#endif
int x360_lzx(unsigned char *src,size_t src_size,unsigned char *dst,size_t dst_size,int window_bits) {
    struct buffer a={src,src_size,0}, b={dst,dst_size,0};
    struct mspack_system sys={0};
    sys.read=read_buffer; sys.write=write_buffer; sys.alloc=alloc_buffer; sys.free=free; sys.copy=copy_buffer; sys.message=message;
    struct lzxd_stream *s=lzxd_init(&sys,(struct mspack_file*)&a,(struct mspack_file*)&b,window_bits,0,32768,(off_t)dst_size,0);
    if(!s) return -1;
    int r=lzxd_decompress(s,(off_t)dst_size); lzxd_free(s);
    return r?r:(b.pos==dst_size?0:-2);
}
