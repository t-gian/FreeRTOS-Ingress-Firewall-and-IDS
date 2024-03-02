/*
 * FreeRTOS V202212.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * https://www.FreeRTOS.org
 * https://github.com/FreeRTOS
 *
 */

/******************************************************************************
 * This project provides two demo applications.  A simple blinky style project,
 * and a more comprehensive test and demo application.  The
 * mainCREATE_SIMPLE_BLINKY_DEMO_ONLY setting in main.c is used to select
 * between the two.  See the notes on using mainCREATE_SIMPLE_BLINKY_DEMO_ONLY
 * in main.c.  This file implements the simply blinky version.
 *
 * This file only contains the source code that is specific to the basic demo.
 * Generic functions, such FreeRTOS hook functions, are defined in main.c.
 ******************************************************************************
 *
 * main_blinky() creates one queue, one software timer, and two tasks.  It then
 * starts the scheduler.
 *
 * The Queue Send Task:
 * The queue send task is implemented by the prvQueueSendTask() function in
 * this file.  It uses vTaskDelayUntil() to create a periodic task that sends
 * the value 100 to the queue every 200 (simulated) milliseconds.
 *
 * The Queue Send Software Timer:
 * The timer is an auto-reload timer with a period of two (simulated) seconds.
 * Its callback function writes the value 200 to the queue.  The callback
 * function is implemented by prvQueueSendTimerCallback() within this file.
 *
 * The Queue Receive Task:
 * The queue receive task is implemented by the prvQueueReceiveTask() function
 * in this file.  prvQueueReceiveTask() waits for data to arrive on the queue.
 * When data is received, the task checks the value of the data, then outputs a
 * message to indicate if the data came from the queue send task or the queue
 * send software timer.
 */

/* Standard includes. */
#include <stdio.h>
#include <stdlib.h>

/* Kernel includes. */
#include "FreeRTOS.h"
#include "task.h"

/*-----------------------------------------------------------*/
//START RAM DEMO VARIABLES/FUNCTIONS

static void showCurrentMemAllocation(void);
static int loadCurrentStructure(void*address,char label);
static int loadAndPrintCurrentStructure(void*address,char label);
static int emptyAndPrintCurrentStructure(void*address,size_t size);
static int emptyCurrentStructure(void*address,size_t size);
static int getBaseAddress(void * address);

static void printSeparatorRow(uint8_t index);
static void printMemRow(uint8_t index);
static void printMemBorder(uint8_t size);
static void printMemHeader(void);
static void printPaddingRows(int numOfRows);
static void printAllocation(size_t size);
static void showTimer(int timeToWait);
static void startMemDemo();

static StaticTask_t xTaskBuffer;
static StackType_t xStack[configMINIMAL_STACK_SIZE*3];

HeapRegion_t demoHeapRegions[] =
{
   { ( uint8_t * ) BASE_ADDRESS, BSIZE_HEX },
   { ( uint8_t * ) BASE_ADDRESS+BSIZE_HEX, BSIZE_HEX },
   { ( uint8_t * ) BASE_ADDRESS+BSIZE_HEX*2, BSIZE_HEX },
   { ( uint8_t * ) BASE_ADDRESS+BSIZE_HEX*3, BSIZE_HEX },
   { ( uint8_t * ) BASE_ADDRESS+BSIZE_HEX*4, BSIZE_HEX },
   { ( uint8_t * ) BASE_ADDRESS+BSIZE_HEX*5, BSIZE_HEX },
   { NULL, 0 }//<< Terminates the array.
};

static char ramDemoImg[NUM_OF_BLOCKS][AVAL_MEM_SIZE] = {{'\0'}};  //array to use for the demo (to show a visual rappresentation)

//END RAM DEMO VARIABLES/FUNCTIONS

/*-----------------------------------------------------------*/

void main_mem_demo( void )
{
    vPortDefineHeapRegions(demoHeapRegions);//init the HEAP region

    srand((unsigned int)xTaskGetTickCount());

    if (DEBUG){
        for(int i = 0; demoHeapRegions[i].pucStartAddress != NULL;i++)
            printf("\nCURRENT REGION: %x with size %d",demoHeapRegions[i].pucStartAddress,demoHeapRegions[i].xSizeInBytes);
        printf("NUM BLOCKS: %d, AVAL MEM: %d",NUM_OF_BLOCKS,AVAL_MEM_SIZE);
    }

    xTaskCreateStatic(
        startMemDemo,
        "MemDemo",
        configMINIMAL_STACK_SIZE*3,
        NULL,
        1,
        xStack,
        &xTaskBuffer
    );

    vTaskStartScheduler();


    /* If all is well, the scheduler will now be running, and the following
     * line will never be reached.  If the following line execute, then
     * there was insufficient FreeRTOS heap memory available. */
    for( ; ; )
    {
    }
}

static void startMemDemo(){


    int sz[TEST_ADD_NUM] = {0}, i,currSz,j;
    size_t szAsked[TEST_ADD_NUM] = {0};
    char *ptrArr[TEST_ADD_NUM];
    char labelArr[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    if (TEST_ADD_NUM > 26 || TEST_ADD_NUM < 1){
        printf(">> INVALID NUMBER OF TEST CASES! MIN IS 1 AND MAX IS 26!");
        return;
    }

    printf("\n\n\n### STARTING DYNAMIC MEM ALLOCATION DEMO ###\n\nMEM SIZE: %d BYTES\nMEM BASE ADDRESS: 0x%x", MEM_SIZE, BASE_ADDRESS);
    printf("\nEMPTY BLOCK STRUCTURE:\n\n");
    showCurrentMemAllocation();

    while (1){

        vTaskDelay(DELAY);

        printf("\n\n\t\t\t### BEGINNING TO ALLOCATE THE MEMORY ###\n\n");
        showTimer(DELAY_START);

        //start to allocate the memory
        for(i = 0; i < TEST_ADD_NUM; i++){
            currSz = rand() % (MEM_SIZE-xHeapStructSize-CURRENT_PADDING) + 1;
            szAsked[i] = sizeof(char)*currSz;
            printAllocation(szAsked[i]);
            ptrArr[i] = pvPortMalloc(szAsked[i]);
            sz[i] = loadAndPrintCurrentStructure(ptrArr[i],labelArr[i]);
            showTimer(DELAY_ALLOCATION);
        }

        printf("\n\t\t\t### BEGINNING TO FREE THE MEMORY ###\n\n");
        showTimer(DELAY_START);

        //start to free the allocated memory
        for(i = 0; i < TEST_ADD_NUM; i++){
            if (ptrArr[i] != NULL){
                emptyAndPrintCurrentStructure(ptrArr[i],sz[i]);
                showTimer(DELAY_FREE);
            }
        }

        //Reset the separator block array (used to draw the mem block splits)
        for(i = 0; i < NUM_OF_BLOCKS; i++)
            for(j = 0; j < NUM_OF_BLOCKS; j++)
                separatorBlockArr[i][j] = '\0';
    }
}

/*-----------------------------------------------------------*/

static void printAllocation(size_t size){
    if (size > 1)
        printf("\n>> Starting the allocation of %d bytes...\n", (int)size);
    else
        printf("\n>> Starting the allocation of %d byte...\n", (int)size);
}

/*-----------------------------------------------------------*/

static void showTimer(int seconds){
    if (seconds > 100){
        printf("\n>> FATAL! timers > 100s are UNSUPPORTED!\n");
    } else {
        printf("\n\nWaiting: ");
        while(seconds){
            printf("%d...",seconds--);
            vTaskDelay(1000);
        }
        printf("\n");
    }
}


/*-----------------------------------------------------------*/

static int emptyAndPrintCurrentStructure(void*address,size_t size){

    int res = -1;

    if (address != NULL && size > 0){
        res = emptyCurrentStructure(address,size);

        vPortFree(address);

        if (!res)showCurrentMemAllocation();
    }

    return res;
}

/*-----------------------------------------------------------*/

static int emptyCurrentStructure(void*address,size_t size){
    int res = 0;

    if (address != NULL){

        int startOffset = getBaseAddress(address);

        if (startOffset >= 0 && size > 0){

            if(DEBUG)
                printf(">> START OFFSET FOR FREE: %x, TOTAL SIZE TO FREE: %d",address,(int)size);


            for(int i = startOffset%AVAL_MEM_SIZE,j = 0,r = startOffset/AVAL_MEM_SIZE,c
                ; j < size
                ; j++){

                if ((startOffset+j)/AVAL_MEM_SIZE > r){//next mem block is reached
                    ++r;
                }

                c = (i+j)%AVAL_MEM_SIZE;

                if (r == NUM_OF_BLOCKS){
                    printf("\n>> MEM OVERFLOW! <<\n");
                    res = -1;
                    break;
                }

                ramDemoImg[r][c] = '\0';
            }
        }

    }

    return res;
}


/*-----------------------------------------------------------*/


static int loadAndPrintCurrentStructure(void*address,char label){
    int res = loadCurrentStructure(address,label);
    vTaskDelay(DELAY*1000);

    if (res > 0) showCurrentMemAllocation();

    return res;
}

/*-----------------------------------------------------------*/

static int loadCurrentStructure(void* address,char label){
    int res = -1;

    if (address != NULL && memPlusAlignment > 0){

        /*
        * startOffset  -> the actual offset of the memory allocated
        * totalSize -> the total size allocated
        *
        * */
        int startOffset = getBaseAddress(address);

        /*
         * Assert that:
         *  - the pointer offset is >= 0 (should not go below 8 counting the heap structure)
         *  - the starting offset is >= 0 (should start from 0)
         *  - the starting offset is not greater than the number of available bits
         */
        if(startOffset >= 0 && startOffset < NUM_OF_BLOCKS*AVAL_MEM_SIZE){

            int totalSize = (memPlusAlignment+xHeapStructSize), heapStructPlusAlignment = (xHeapStructSize+alignement);

            printf("\n>> Memory for label '%c' has been allocated: \t[ 0x%x , 0x%x ]\n>pointer address starting at \t\t\t0x%x\n>real starting address \t\t\t\t0x%x\n>user asked for (bytes): \t\t\t%d\n>alignement required (bytes): \t\t\t%d\n>space required for the heap structure (bytes): %d\n>total size allocated (bytes): \t\t\t%d\n",
            label,(address-xHeapStructSize),(address+memPlusAlignment-1),address,(address-xHeapStructSize),(memPlusAlignment-alignement),alignement,xHeapStructSize,(memPlusAlignment+xHeapStructSize));

            if (DEBUG) printf(">> START OFFSET : %d\n",startOffset);

            char currChar;

            for(int i = startOffset%AVAL_MEM_SIZE,j = 0,r = startOffset/AVAL_MEM_SIZE,c,heapStructInt = (int)xHeapStructSize
                ; j < totalSize
                ; j++){

                if ((startOffset+j)/AVAL_MEM_SIZE > r){//next mem block is reached
                    ++r;
                }

                if (r == NUM_OF_BLOCKS){
                    printf("\n>> FATAL MEM OVERFLOW! <<\n");
                    res = -3;
                    break;
                }

                c = (i+j)%AVAL_MEM_SIZE;

                if (j < heapStructInt)
                    currChar = '/';
                else if (j < heapStructPlusAlignment)
                    currChar = '>';
                else
                    currChar = label;

                ramDemoImg[r][c] = currChar;
            }

            alignement = 0;//reset the number of alignement bytes

            if (res == -1)
                res = totalSize;

        } else {
            if (startOffset >= NUM_OF_BLOCKS*AVAL_MEM_SIZE){
                printf("\n>> MEM OVERFLOW! the starting index is out of the memory blocks. <<\n");
            } else {
                printf(">> FATAL: negative offsets: starting offset - %d",startOffset);
            }
        }
    } else {
        printf(">> ERROR: no memory was allocated!\n");
    }

    return res;
}

/*-----------------------------------------------------------*/

static int getBaseAddress(void * address){

    int res = -1;

    if (address != NULL){

        int paddingOffset;

        res = (int)((address - xHeapStructSize)-BASE_ADDRESS);//calculate the actual starting address (from 0 to AVAL_MEM_SIZE*NUM_OF_BLOCKS)

        if ((paddingOffset = res / MEM_SIZE) > 0)
                res-=CURRENT_PADDING*paddingOffset;
    }

    return res;
}


/*-----------------------------------------------------------*/

static void showCurrentMemAllocation( void ){

    int i,paddingStart,memBorderSize;

    printf("\n>> MEM STATUS:\n> Every char is a BYTE, every different letter corrisponds to a specific request of memory\n> '-' stands for an available byte\n> '/' stands for a byte occupied by the HEAP structure of FreeRTOS\n> '>' stands for an alignement byte\n> '—' between blocks represents a block split by FreeRTOS creating a smaller free block\n> '—' between blocks represents a block split by FreeRTOS creating external fragmentation\n\n");

    memBorderSize = ((NUM_OF_BLOCKS)*BYTE_PER_ROW+NUM_OF_BLOCKS)*2-1;

    //Print the theader
    printMemHeader();

    //Print the upper border
    printMemBorder(memBorderSize);

    //calculate the first row of padding
    paddingStart = (MEM_SIZE-CURRENT_PADDING)/BYTE_PER_ROW;

    //Print the cells
    for(i = 0; i < paddingStart;i++){
        printMemRow(i);
        printSeparatorRow(i);
    }

    //print the padding
    printPaddingRows(MEM_SIZE/BYTE_PER_ROW-paddingStart);

    //Print the lower border
    printMemBorder(memBorderSize);
    printf("\n<<");
}

/*-----------------------------------------------------------*/

static void printMemHeader(void){//prints the header for the cells
    for(int i = 0,j; i < NUM_OF_BLOCKS; i++){
        if(BYTE_PER_ROW%2==0)//in case of odd numbers do NOT print the | between them
            printf("|");

        for(j = 0; j < (BYTE_PER_ROW)/2;j++)
            printf(" ");

        if(NUM_OF_BLOCKS > 9)
            printf("BLOCK #%d",i+1);
        else
            printf("BLOCK #0%d",i+1);

        for(j = 0; j < (BYTE_PER_ROW)/2;j++)
            printf(" ");

    }
    printf("|\n");
}

/*-----------------------------------------------------------*/

static void printMemBorder(uint8_t size){//prints a border for the cells
    printf(" ");
    for(int i = 0; i < size;i++)
        printf("—");
    printf("\n");
}

/*-----------------------------------------------------------*/

static void printMemRow(uint8_t index){//Prints a memory block row(the same row of all the blocks)
    char nextChar;

    printf("|");
    for(int j = 0,k=BYTE_PER_ROW*index; j < NUM_OF_BLOCKS*BYTE_PER_ROW;j++,k++){
        if(j%BYTE_PER_ROW==0 && j > 0){
            printf(" |");
            k=BYTE_PER_ROW*index;
        }

        nextChar = ramDemoImg[j/BYTE_PER_ROW][k];

        if (nextChar == '\0'){
           nextChar = '-';
        }

        printf(" %c",nextChar);
    }
    printf(" |\n");
}

/*-----------------------------------------------------------*/

static void printSeparatorRow(uint8_t index){//Prints the block splits done by FreeRTOS
    printf("| ");
    for(int j = 0,k; j < NUM_OF_BLOCKS; j++){

        if (j > 0)
            printf(" | ");

        for(k = 0; k < BYTE_PER_ROW*2-1; k++){
            if (separatorBlockArr[j][index] == 1 ){
                printf("—");
            } else if (separatorBlockArr[j][index] == 2 ){
                printf(":");
            } else {
                printf(" ");
            }
        }
    }
    printf(" |\n");
}

/*-----------------------------------------------------------*/

static void printPaddingRows(int numOfRows){//prints the rows used as MEM PADDING by FreeROTS

    char currChar;

    for(int i = 0,r; i < numOfRows*2;i++){
        if (i%2 != 0) {
            currChar = ' ';
        } else {
            currChar = '#';
        }
        printf("| ");

        for(r = 0; r < NUM_OF_BLOCKS*BYTE_PER_ROW*2-NUM_OF_BLOCKS; r++){
            if (r % (BYTE_PER_ROW*2-1) == 0 && r > 0)
                printf(" | ");
            printf("%c",currChar);
        }

        printf(" |\n");
    }
}

/*-----------------------------------------------------------*/

