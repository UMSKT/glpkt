# G legacy product key tool

The G stands for something I forgot. Probably either gay or Go.

glpkt verifies product keys that are consumed by pidgen.dll. Examples include Windows 95 through XP as well as Windows Server 2003 and XP x64, but also SQL Server 2000 and Visual Studio .NET.

It can also generate new BINKs if you want to make your own product keys based around this code for some reason. Note that it cannot break existing BINKs, so it cannot be used for piracy.

**Usage**:

```
$ glpkt -i DLL/BINK [-i DLL/BINK...] product_key...
$ glpkt -G -i output.bink binkResourceId
```

In the first mode, it verifies product keys against a pidgen.dll (it will extract the BINKs from the resource section automatically) or against a pre-extracted BINK. Multiple DLLs/BINKs can be given by specifying -i multiple times. Multiple product keys can also be given.

In the second mode, it generates a new BINK. This should only take a few seconds. Note that Microsoft has used BINK resource IDs up to 0x70, so you may wish to avoid a namespace collision by using different IDs.

**Flags**:

`-G` specifies to generate a BINK instead

`-i` specifies a BINK or DLL (input; output for generating a BINK)

`-v` runs very verbosely for debugging/writing your own implementation

**License**: Dedicated to the public domain.

