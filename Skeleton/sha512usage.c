# include <string.h>
# include <openssl/sha.h>
# include <openssl/hmac.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <assert.h> 

// For compiling type in: gcc sha512usage.c -o password -lcrypto 


int getRandBytes(unsigned char * ptr, unsigned num_bytes){
        int ret = RAND_bytes(ptr, num_bytes) ;
        if(ret != 1) return -1 ;
        return ret ;
}


 
int main() {
	char pass[1024] ; 
	char salt[32]; 

	while(scanf("%s",pass)==1){
		unsigned char digest[SHA512_DIGEST_LENGTH]; 
		SHA512_CTX ctx;
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, pass, strlen(pass));
		assert(getRandBytes(salt, 32) != -1 ) ; 
		SHA512_Update(&ctx, salt, 32);
		SHA512_Final(digest, &ctx);
	
		char mdString[SHA512_DIGEST_LENGTH*2+1];
		for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
		    sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
	 
		printf("SHA512 hash value: %s\n", mdString);
		printf("LEN: %d\n",SHA512_DIGEST_LENGTH); 

	}

    return 0;
}
