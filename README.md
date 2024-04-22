# SharpVenoma

<div align="center">
  <br>
  <a href="https://twitter.com/intent/follow?screen_name=ProcessusT" title="Follow"><img src="https://img.shields.io/twitter/follow/ProcessusT?label=ProcessusT&style=social"></a>
  <br>
  <h1 >
    C# reimplementation of <a href="https://github.com/ProcessusT/Venoma">Venoma</a>
  </h1>
  <br>
  <span style="font-size:11px;">Another C# Cobalt Strike beacon dropper with custom indirect syscalls execution</span><br />
  <br>
</div>

<div align="center">
<img src="https://github.com/ProcessusT/SharpVenoma/raw/main/assets/edr2.png" width="80%;"><br>
<img src="https://github.com/ProcessusT/SharpVenoma/raw/main/assets/edr1.png" width="80%;"><br>
</div>

<br>
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

<br /><br />


## Usage
<br />
Generate your raw payload and use the aes.py file to encrypt the data :<br /><br />
<img src="https://github.com/ProcessusT/SharpVenoma/raw/main/assets/payload_encode.png" width="60%;"><br><br />
Update the source code and choose what you want to execute :<br /><br />
<img src="https://github.com/ProcessusT/SharpVenoma/raw/main/assets/payload_update.png" width="60%;"><br>




<br /><br /><br />
