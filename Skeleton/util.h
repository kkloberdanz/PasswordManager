#ifndef _UTIL_H_   /* Include guard */
#define _UTIL_H_

# include <string.h> 
# include <malloc.h> 
# include <assert.h> 

# define MAX_USER_NAME_SIZE 33 
# define SALT_SIZE 32 
# define HASHED_PASSWORD_SIZE (SHA512_DIGEST_LENGTH)


# define OKAY   1
# define ERROR -1

# define TOO_LONG  -1 
# define TOO_SHORT  -2 
# define INVALID_CHARACTER -3 

//This function checks whether the username has the right length and contains only valid characters ... 
int username_okay(unsigned char * user){
	int len = strlen( user ) ; 
	if(len >= 32) { printf("Error: Username too long\n"); return TOO_LONG;}  
	if(len < 6) {printf("Error: Username too short\n"); return TOO_SHORT ;} 
	int i ; 
	for(i=0;i<len;++i){
		if((user[i]>='0' && user[i]<='9')||(user[i]>='a' && user[i] <= 'z')||(user[i]>='A' && user[i] <= 'Z')) continue ; 
		printf("Error: Username contains invalid character: %c\n", user[i]); 
		return INVALID_CHARACTER ; 
	}
	return OKAY ; 
}

//This function checks whether the password has the right length and contains only valid characters ... 
int password_okay(unsigned char * password)
{
	int len = strlen(password) ; 	
	if(len >= 32) { printf("Error: Password too long\n"); return TOO_LONG;}  
	if(len < 9) {   printf("Error: Password too short\n"); return TOO_SHORT ;}  
	int i ; 
	for(i=0;i<len;++i)
	{
		if((password[i]>='0' && password[i]<='9')||(password[i]>='a' && password[i] <= 'z')||(password[i]>='A' && password[i] <= 'Z')) continue ; 
		if(password[i]=='@' || password[i]=='#' || password[i]=='$' || password[i]== '%' || password[i]== '&' || password[i]=='*' || password[i]=='+' || password[i]=='=' || password[i]=='(' || password[i]== ')') continue ;  
		printf("Error: Password contains invalid character: %c\n", password[i]); 
		return INVALID_CHARACTER ; 
	}
	return OKAY ; 

}


//Copies binary data from src to dst 
// It assumes both dst and src are allocated 
void binary_copy(unsigned char *dst, unsigned char * src, int sz)
{
	int i ; 
	for(i=0;i<sz;++i)dst[i]=src[i];
}

//Compares two binary values 
//Returns 1 when they are equal, otherwise returns -1 
int binary_compare(unsigned char * op1, unsigned int sz1, unsigned char * op2, unsigned int sz2)
{
	if(sz1 != sz2) return -1 ; 
	int i ;
	for(i=0;i<sz1;++i)
	{
		if(op1[i]==op2[i])continue;
		return -1; 
	}
	return 1 ; 
}


//Utility function for converting hexadecimal digit to its decimal counterpart 
unsigned char hex_digit_to_decimal(unsigned char ch){
        if(ch >='0' && ch <='9'){
                return (unsigned) (ch-'0') ;
        }
        else if(ch>='a' && ch<='f'){
                return (unsigned)(ch-'a'+10);
        }
        else
        {
                printf("ERROR: HEX-TO-DECIMAL: UNKNOWN DIGIT %c\n",ch);
                assert(0);
                return 0;
        }
}


//It is required for both hex_string and  byte_array to be allocated with proper space ...
int hex_array_to_byte_array(unsigned char * hex_string, unsigned char * byte_array)
{
        if(!byte_array){
                printf("ERROR: Byte Array Not allocated ..\n");
                return -1 ;
        }
        int len = strlen(hex_string);
        if(len%2 !=0){
                printf("ERROR: BAD HEX STRING: ODD LENGTH\n");
                return -1;
        }
        // byte_array = (unsigned char *) malloc(sizeof(unsigned char) * (len/2) + 1) ;
        int i ;
        for(i=0;i<(len-1);i+=2){
                byte_array[i/2] = (unsigned char)((hex_digit_to_decimal(hex_string[i]) << 4) | hex_digit_to_decimal(hex_string[i+1])) ;

        }
        return (len/2);
}

//It is required that both byte_array and hex_string are already allocated with proper space ...
int byte_array_to_hex_array(unsigned char * byte_array, unsigned int num_bytes,  unsigned char* hex_string)
{
        if(!hex_string){
                printf("ERROR: Hex String not allocated ....");
                return -1 ;
        }
        int i , j = 0;
        unsigned char buff[1024];
        for(i=0;i<num_bytes;++i){
                sprintf(buff,"%02x",byte_array[i]);
                //printf("BUFF: %c-%c\n",buff[0],buff[1]);
                hex_string[2*i]=buff[0];
                hex_string[2*i+1]=buff[1];
        }
        hex_string[2*i] = (unsigned char)0 ;
}


// Linked list data structure for storing the password file ... 
struct passwordEntry
{
	unsigned char user_name[MAX_USER_NAME_SIZE]; // in ASCII 
	unsigned char salt[SALT_SIZE] ; // in binary 
	unsigned char hashed_password[HASHED_PASSWORD_SIZE]  ; // in binary 
	struct passwordEntry *nextEntry ; 
};

typedef struct passwordEntry LLEntry ; 

LLEntry * head ; 


/*Takes a user name and searches whether the user is present in the password data-structure*/
/*If it finds the user it returns the pointer to the element of the linked list which holds the user's entry*/
/*If it cannot find the user, it return NULL */
LLEntry* find_user(unsigned char * uname)
{
	if(head == NULL) return NULL ; 
	LLEntry * temp = head ; 

	while(temp){
		if(strcmp(uname, temp->user_name)==0)return temp; 
		temp=temp->nextEntry ; 		
	}
	return NULL ; 
}



// Inserts the entry into the linked list 
//It takes as argument the username, the salt value, and the hashed password 
void 
push_back(unsigned char * uname, unsigned char * slt, unsigned char * hPassword)
{
	if(head == NULL){
		head = (LLEntry*) malloc(sizeof(LLEntry)) ; 
		strcpy((head)->user_name, uname); 
		binary_copy((head)->salt, slt,SALT_SIZE); 
		binary_copy((head)->hashed_password, hPassword, HASHED_PASSWORD_SIZE);
		assert(head != NULL) ; 
		(head)->nextEntry = NULL ; 
		return ; 
	}
	if(find_user(uname)!=NULL){
		printf("Error: Duplicate entry for user %s\n",uname); 
		return ; 
	}

	LLEntry * tmp = head ; 
	while(tmp->nextEntry != NULL){
		tmp=tmp->nextEntry ; 
	} 
	LLEntry *newNode = (LLEntry*) malloc(sizeof(LLEntry)); 
	strcpy(newNode->user_name, uname); 
	binary_copy(newNode->salt, slt,SALT_SIZE); 
	binary_copy(newNode->hashed_password, hPassword, HASHED_PASSWORD_SIZE);
	newNode->nextEntry = NULL ; 
	tmp->nextEntry = newNode ;
	return ; 
}



//Looks for the user with the username uname and deletes the entry for it from the data structure 
void
delete_node(unsigned char * uname)
{
	if(head==NULL){
		printf("Error: Password data structure empty\n");
		return ; 
	}
	//Find the node ... 
	LLEntry * current = find_user(uname) ; 
	if(current == NULL){
		printf("Error: Cannot find user\n");
		return ; 
	}
	if(current == head){
		LLEntry * tmp = head ; 
		head = (head)->nextEntry ; 
		free(tmp) ; 
		return ; 

	}
	LLEntry * previous = head ; 
	while(previous){
		if(previous->nextEntry == current) break ; 
		previous = previous->nextEntry ; 
	}
	if(previous){
		previous->nextEntry = current->nextEntry ; 
		free(current); 
		return ;
		
	}
	else{
		printf("Error: Couldn't find the user in delete user which is strange\n");
		assert(0); 
		return ; 
	}

}

//Utility function used by the delete_entire_list function 
void deletelist(LLEntry **node)
{
	if(*node==NULL)return ; 
	deletelist(&(*node)->nextEntry) ;
	free(*node) ; 
}


//This function frees the linked list data structure holding the password file 
void 
delete_entire_list(){
	
 	deletelist(&head) ; 
	
}


//This function loads the password file into the memory 
void 
parse_line_load_data_structure(FILE * fin)
{
	unsigned char buff[1024] ; 
	unsigned char uname[MAX_USER_NAME_SIZE];
	unsigned char slt[SALT_SIZE*2+1] ;  //hexadecimal representation 
	unsigned char hPassword[HASHED_PASSWORD_SIZE*2+1] ; //hexadecimal representation 
	unsigned char Binaryslt[SALT_SIZE] ;  //BINARY representation 
	unsigned char BinaryhPassword[HASHED_PASSWORD_SIZE] ; //BINARY representation 

	unsigned char *ptr ;
	while(fscanf(fin, "%s", buff)==1)
	{
		int counter = 0 ; 
		ptr = strtok(buff, ":"); 
		while(ptr){
			if(counter==0)strcpy(uname, ptr);
			else if(counter==1)strcpy(slt, ptr);
			else if(counter==2)strcpy(hPassword, ptr);
			else assert(0);
			++counter; 		
			ptr = strtok(NULL, ":"); 
		}
		assert( hex_array_to_byte_array(slt,Binaryslt) == SALT_SIZE); 
		assert( hex_array_to_byte_array(hPassword,BinaryhPassword) == HASHED_PASSWORD_SIZE) ; 
		
		push_back(uname, Binaryslt, BinaryhPassword) ; 
	}
	//return head ; 
}


//This function dumps the linked list data structure into the file identified with the file descriptor 
void dump_datastructure_into_file( FILE * fout)
{

	LLEntry *iter = head ; 
	unsigned char slt[SALT_SIZE*2+1] ;  //hexadecimal representation 
	unsigned char hPassword[HASHED_PASSWORD_SIZE*2+1] ; //hexadecimal representation 
	while(iter){

		fprintf(fout, "%s",iter->user_name) ; 
		int unused = byte_array_to_hex_array(iter->salt, SALT_SIZE, slt) ; 
		unused = byte_array_to_hex_array(iter->hashed_password, HASHED_PASSWORD_SIZE, hPassword); 
		fprintf(fout,":%s:%s\n",slt,hPassword);

		iter = iter->nextEntry ; 
	}	
	
}


//This function dumps the internal data structure in console 
//This can be used for debugging your code 
void dump_structure()
{

	LLEntry *iter = head ; 
	unsigned char slt[SALT_SIZE*2+1] ;  //hexadecimal representation 
	unsigned char hPassword[HASHED_PASSWORD_SIZE*2+1] ; //hexadecimal representation 
	while(iter){

		printf("%s",iter->user_name) ; 
		int unused = byte_array_to_hex_array(iter->salt, SALT_SIZE, slt) ; 
		unused = byte_array_to_hex_array(iter->hashed_password, HASHED_PASSWORD_SIZE, hPassword); 
		printf(":%s:%s\n",slt,hPassword);
		iter = iter->nextEntry ; 
	}	
	
}



//This function creates num_bytes number of random bytes and stores it in the ptr 
//It assumes ptr is allocated already 
int getRandBytes(unsigned char * ptr, unsigned num_bytes){
        int ret = RAND_bytes(ptr, num_bytes) ;
        if(ret != 1) return -1 ;
        return ret ;
}


void update_user_password(unsigned char * user, unsigned char *SALT, unsigned char *HASHED_PASSWORD)
{
	LLEntry * usr = find_user( user ) ; 
	binary_copy(usr->salt, SALT, SALT_SIZE); 
	binary_copy(usr->hashed_password, HASHED_PASSWORD, HASHED_PASSWORD_SIZE) ; 
}



#endif
