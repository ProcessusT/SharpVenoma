# SharpVenoma

<div align="center">
  <br>
  <a href="https://twitter.com/intent/follow?screen_name=ProcessusT" title="Follow"><img src="https://img.shields.io/twitter/follow/ProcessusT?label=ProcessusT&style=social"></a>
  <br>
  <h1 >
    CSharp reimplementation of <a href="https://github.com/ProcessusT/Venoma">Venoma</a>, another C++ Cobalt Strike beacon dropper with custom indirect syscalls execution<br />
  </h1>
  <br><br>
</div>

> A custom CSharp raw beacon dropper with :<br /><br />
> <strong>DLL Unhooking (Perun's fart)</strong><br />
> <strong>ETW Patching</strong><br />
> <strong>AMSI Patching</strong><br />
> <strong>EnumPageFilesW execution</strong><br />
> <strong>Early Bird APC Execution</strong><br />
> <strong>Indirect syscall execution</strong><br />
> <br />
<br>
<h4>All functions are included, choose what you need and remove anything else before compiling.</h4>
<br>
<div align="center">
<img src="https://github.com/ProcessusT/SharpVenoma/raw/main/assets/edr1.png" width="100%;"><br>
</div>
<br>

<br /><br />


## Usage
<br />
Generate your raw payload and use the aes.py file to encrypt the data :<br />
<div align="center">
<img src="https://github.com/ProcessusT/SharpVenoma/raw/main/assets/payload_encode.png" width="100%;"><br>
</div>
Update the source code and choose what you want to execute :<br />
<div align="center">
<img src="https://github.com/ProcessusT/SharpVenoma/raw/main/assets/payload_update.png" width="100%;"><br>
</div>




<br /><br /><br />
