                            _____       _         _           _         
         /\                / ____|     | |       | |         | |        
        /  \   _ __  _ __ | |  __  __ _| |_ ___  | |     __ _| |__  ___ 
       / /\ \ | '_ \| '_ \| | |_ |/ _` | __/ _ \ | |    / _` | '_ \/ __|
      / ____ \| |_) | |_) | |__| | (_| | ||  __/ | |___| (_| | |_) \__ \
     /_/    \_\ .__/| .__/ \_____|\__,_|\__\___| |______\__,_|_.__/|___/
              | |   | |                                                 
              |_|   |_|    

# IDA Script

"ida_resolver_api.py" is a script that can be used in IDA pro to automate APIs resolution on Dridex samples.

## Usage

Make sure to update the main function parameters with the decryption key and the offset where the "API resolver" function is located.

```python
# main(xor_key, resolver_function)
main(0xCBCB795B, 0x414F60)
```