# CATALYST

## What is Catalyst ?
 Catalyst is a heavily key-dependent stream cipher that can be used to encrypt or decrypt data. The key-dependence of this algorithms is used to generate an algorithm that will make it impossible to recover the data if the wrong key is used since even a slight variation of bits in the key will result in completely different metadata used by the algorithm to determine which constants and which functions to use, which will in turn return a plain text completely different than the one corresponding to the cipher if the right key was provided.

## This repository contains the following elements :
- **sha3** an implementation of the SHA3 functions (including the SHAKE ones).
- **devcatalyst** the library that may be used in another program to use the catalyst encryption algorithm.
- **catalyst** a basic command-line interface to the **devcatalyst** library

## How to build ? - For development
 you first need to download the repository using the mean of your choice, using git will require you to clone the repository :
 ```bash
 git clone https://AProgrammablePhoenix/Catalyst
 ```
 (note that if this URL does not work, it means I might have changed my username, in this case use the URL GitHub provides you when you click on the download options)

 Then you need to build the source code :  
 On Ubuntu-like Linux distributions:
 1. Create a build directory using
    ```bash
    mkdir build
    ```
 2. Then run cmake using
    ```bash
    cmake .. -DCMAKE_BUILD_TYPE=Release
    ```

 3. 1. If you only want to use the Catalyst library (and not the command-line interface) :
    ```bash
    make devcatalyst
    ```
    2. If you want to build everything, just run :
    ```bash
    make
    ```
 4. Finally, just link the library (**devcatalyst**) to your project, and you are ready to go !

 5. (optional) If you want to easily use the **catalyst** command, or to link the **devcatalyst** library to your project, then you should consider installing the project onto your system by running :
 ```bash
   sudo make install
 ```

## How to build ? - For direct use
 Follow the steps of **How to build ? - For development**, use step **3.2** instead of **3.1**, ignore step **5.**

## Only want the SHA3 library ?
 Follow the steps of **How to build ? - For development**, ignore step **5.** and instead of building using step **3.1** or **3.2**, use :
 ```bash
 make sha3
 ```

## How to use the command-line interface ?
 The command-line interface is actually very straightforward to use, the command is (assuming you are in the build directory) :
 ```bash
 ./catalyst <-e|-d>[-x][-f]
 ```
 where :
 - **-e**   : encrypts data with specified key, data and key are both strings
 
 - **-ex**  : encrypts data with specified key, data and key are both hexadecimal
 
 - **-ef**  : encrypts file with specified key, data is the name of the file to encrypt, key is a string
 
 - **-exf** : encrypts file with specified key, data is the name of the file to encrypt, key is hexadecimal

 - **-d**   : decrypts data with specified key, data and key are both strings

 - **-dx**  : decrypts data with specified key, data and key are both hexadecimal

 - **-df**  : decrypts file with specified key, data is the name of the file to encrypt, key is a string

 - **-dxf** : decrypts file with specified key, data is the name of the file to encrypt, key is hexadecimal

 Options are position-sensitive, meaning that (for instance), **-dxf** is valid, but **-dfx** is not, please take the position of the options as described above into account when calling the catalyst command-line interface.  
 Options using a file as input will output the encrypted/recovered data into a file with the same name, but with a different extension (**.out** by default)