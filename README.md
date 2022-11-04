# ♻️ EcoHook ♻️

## How does it work? 🤓
it's simply puts all the usual hooking stuff not in a newly allocated space, but rather in the spaces (padding) between functions. Almost nothing can utilize this space, because it usually doesn't surpass 16 bytes. Which quite frankly is just enough for JMP and some address. The pros of this approach is that the code doesn't have to allocate new space, which means that it doesn't call any *detected* windows functions. Unless you count memcpy as detected. For more information just look at the code. Some parts are commented, some are not (good luck).

## Is it detected? 🤡
Yes, it's obviously detected, just like every other basic way of hooking. If you do things *correctly* tho, you can make this tool *ud*.

## How to detect the hook? 😈
Just get the first 2 bytes from the address of the function you are trying to protect and check if they are E9, or FF or any other call / jmp instruction.

## Updates 🤣
Ye, I plan on adding a feature called *unhooking*, very crazy and advanced stuff, I know. This will prolly take a few years tho... 🙄 (I either drop out, or graduate from university)

## How to use? 💩
The tool can either use built-in *ReadProcessMemory* function (not recommended), or you can provide it your own read / write functions. To do this (same for read) just set *Hook::CustomWriteMem* to your own custom function, whatever it is, kernel driver, IOCTL etc. Then make sure you set the variable *Hook::isPriviliged* accordingly, this variable should be true if *you* have full access to the target's memory. **If Hook::isPriviliged is false, EcoHook will call VirtualProtect to change the access level!**. Profit!

### ♻️ Keep Recycling! ♻️
