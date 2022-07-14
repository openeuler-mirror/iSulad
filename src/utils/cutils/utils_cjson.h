/*
  Copyright (c) 2009-2017 Dave Gamble and cJSON contributors

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

/*******************************************************************************
 *                         TEMPORARY USE, REPLACE ME!                          *
 *******************************************************************************/

#ifndef UTILS_CUTILS_UTILS_CJSON_H
#define UTILS_CUTILS_UTILS_CJSON_H

#ifdef __cplusplus
extern "C"
{
#endif

/* utils_cjson Types: */
#define utils_cjson_False 0
#define utils_cjson_True 1
#define utils_cjson_NULL 2
#define utils_cjson_Number 3
#define utils_cjson_String 4
#define utils_cjson_Array 5
#define utils_cjson_Object 6
	
#define utils_cjson_IsReference 256
#define utils_cjson_StringIsConst 512

/* The utils_cjson structure: */
typedef struct utils_cjson {
	struct utils_cjson *next,*prev;	/* next/prev allow you to walk array/object chains. Alternatively, use GetArraySize/GetArrayItem/GetObjectItem */
	struct utils_cjson *child;		/* An array or object item will have a child pointer pointing to a chain of the items in the array/object. */

	int type;					/* The type of the item, as above. */

	char *valuestring;			/* The item's string, if type==utils_cjson_String */
	int valueint;				/* The item's number, if type==utils_cjson_Number */
	double valuedouble;			/* The item's number, if type==utils_cjson_Number */

	char *string;				/* The item's name string, if this item is the child of, or is in the list of subitems of an object. */
} utils_cjson;


typedef struct utils_cjson_Hooks {
      //void *(*malloc_fn)(size_t sz);
      void (*free_fn)(void *ptr);
} utils_cjson_Hooks;

/* Supply malloc, realloc and free functions to utils_cjson */
extern void utils_cjson_InitHooks(utils_cjson_Hooks* hooks);


/* Supply a block of JSON, and this returns a utils_cjson object you can interrogate. Call utils_cjson_Delete when finished. */
extern utils_cjson *utils_cjson_Parse(const char *value);
/* Render a utils_cjson entity to text for transfer/storage. Free the char* when finished. */
extern char  *utils_cjson_Print(utils_cjson *item);
/* Render a utils_cjson entity to text for transfer/storage without any formatting. Free the char* when finished. */
extern char  *utils_cjson_PrintUnformatted(utils_cjson *item);
/* Render a utils_cjson entity to text using a buffered strategy. prebuffer is a guess at the final size. guessing well reduces reallocation. fmt=0 gives unformatted, =1 gives formatted */
extern char *utils_cjson_PrintBuffered(utils_cjson *item,int prebuffer,int fmt);
/* Delete a utils_cjson entity and all subentities. */
extern void   utils_cjson_Delete(utils_cjson *c);

/* Returns the number of items in an array (or object). */
extern int	  utils_cjson_GetArraySize(utils_cjson *array);
/* Retrieve item number "item" from array "array". Returns NULL if unsuccessful. */
extern utils_cjson *utils_cjson_GetArrayItem(utils_cjson *array,int item);
/* Get item "string" from object. Case insensitive. */
extern utils_cjson *utils_cjson_GetObjectItem(utils_cjson *object,const char *string);

/* For analysing failed parses. This returns a pointer to the parse error. You'll probably need to look a few chars back to make sense of it. Defined when utils_cjson_Parse() returns 0. 0 when utils_cjson_Parse() succeeds. */
extern const char *utils_cjson_GetErrorPtr(void);
	
/* These calls create a utils_cjson item of the appropriate type. */
extern utils_cjson *utils_cjson_CreateNull(void);
extern utils_cjson *utils_cjson_CreateTrue(void);
extern utils_cjson *utils_cjson_CreateFalse(void);
extern utils_cjson *utils_cjson_CreateBool(int b);
extern utils_cjson *utils_cjson_CreateNumber(double num);
extern utils_cjson *utils_cjson_CreateString(const char *string);
extern utils_cjson *utils_cjson_CreateArray(void);
extern utils_cjson *utils_cjson_CreateObject(void);

/* These utilities create an Array of count items. */
extern utils_cjson *utils_cjson_CreateIntArray(const int *numbers,int count);
extern utils_cjson *utils_cjson_CreateFloatArray(const float *numbers,int count);
extern utils_cjson *utils_cjson_CreateDoubleArray(const double *numbers,int count);
extern utils_cjson *utils_cjson_CreateStringArray(const char **strings,int count);

/* Append item to the specified array/object. */
extern void utils_cjson_AddItemToArray(utils_cjson *array, utils_cjson *item);
extern void	utils_cjson_AddItemToObject(utils_cjson *object,const char *string,utils_cjson *item);
extern void	utils_cjson_AddItemToObjectCS(utils_cjson *object,const char *string,utils_cjson *item);	/* Use this when string is definitely const (i.e. a literal, or as good as), and will definitely survive the utils_cjson object */
/* Append reference to item to the specified array/object. Use this when you want to add an existing utils_cjson to a new utils_cjson, but don't want to corrupt your existing utils_cjson. */
extern void utils_cjson_AddItemReferenceToArray(utils_cjson *array, utils_cjson *item);
extern void	utils_cjson_AddItemReferenceToObject(utils_cjson *object,const char *string,utils_cjson *item);

/* Remove/Detatch items from Arrays/Objects. */
extern utils_cjson *utils_cjson_DetachItemFromArray(utils_cjson *array,int which);
extern void   utils_cjson_DeleteItemFromArray(utils_cjson *array,int which);
extern utils_cjson *utils_cjson_DetachItemFromObject(utils_cjson *object,const char *string);
extern void   utils_cjson_DeleteItemFromObject(utils_cjson *object,const char *string);
	
/* Update array items. */
extern void utils_cjson_InsertItemInArray(utils_cjson *array,int which,utils_cjson *newitem);	/* Shifts pre-existing items to the right. */
extern void utils_cjson_ReplaceItemInArray(utils_cjson *array,int which,utils_cjson *newitem);
extern void utils_cjson_ReplaceItemInObject(utils_cjson *object,const char *string,utils_cjson *newitem);

/* Duplicate a utils_cjson item */
extern utils_cjson *utils_cjson_Duplicate(utils_cjson *item,int recurse);
/* Duplicate will create a new, identical utils_cjson item to the one you pass, in new memory that will
need to be released. With recurse!=0, it will duplicate any children connected to the item.
The item->next and ->prev pointers are always zero on return from Duplicate. */

/* ParseWithOpts allows you to require (and check) that the JSON is null terminated, and to retrieve the pointer to the final byte parsed. */
extern utils_cjson *utils_cjson_ParseWithOpts(const char *value,const char **return_parse_end,int require_null_terminated);

extern void utils_cjson_Minify(char *json);

/* Macros for creating things quickly. */
#define utils_cjson_AddNullToObject(object,name)		utils_cjson_AddItemToObject(object, name, utils_cjson_CreateNull())
#define utils_cjson_AddTrueToObject(object,name)		utils_cjson_AddItemToObject(object, name, utils_cjson_CreateTrue())
#define utils_cjson_AddFalseToObject(object,name)		utils_cjson_AddItemToObject(object, name, utils_cjson_CreateFalse())
#define utils_cjson_AddBoolToObject(object,name,b)	utils_cjson_AddItemToObject(object, name, utils_cjson_CreateBool(b))
#define utils_cjson_AddNumberToObject(object,name,n)	utils_cjson_AddItemToObject(object, name, utils_cjson_CreateNumber(n))
#define utils_cjson_AddStringToObject(object,name,s)	utils_cjson_AddItemToObject(object, name, utils_cjson_CreateString(s))

/* When assigning an integer value, it needs to be propagated to valuedouble too. */
#define utils_cjson_SetIntValue(object,val)			((object)?(object)->valueint=(object)->valuedouble=(val):(val))
#define utils_cjson_SetNumberValue(object,val)		((object)?(object)->valueint=(object)->valuedouble=(val):(val))

#ifdef __cplusplus
}
#endif

#endif // UTILS_CUTILS_UTILS_CJSON_H