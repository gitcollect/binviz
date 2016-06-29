# binviz
Binviz is a dynamic memory changes monitoring tool. 
It enables the dynamic data collection from a running process to the analysis and data representation. 
The tool has capability to assist reverse engineers in analyzing and comprehending dynamic memory evolution and to detect patterns, and outliers that are not obvious using non graphical forms of presentation. 
Binviz is based on binary instrumentation. 
Given a binary executable, binwatch executes the binary in top of a dynamic binary instrumentation framework, monitors the execution, collect changes on memory objects, and finally produce a graph illustrating observed memory objects and their evolution during the execution.

## Usage

> $ ./pin –t binviz_path [options] -- binary

Options:

>  – opset: Supply observation points

>  – dump: Dump process memory at supplied observations points

>  – mapping: List all mapped memory regions

>  – pointer: Resolve pointers

>  – static:Include operations on static memory

>  – trace: Trace the executed instructions

>  – help: Print help message

### Example:


## Authors
- Marouene Boubakri <[marouene.boubakri@eurecom.fr](mailto:marouene.boubakri@eurecom.fr)>
