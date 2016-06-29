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

Linked list is a data structure consisting of a group of memory nodes which together represent a sequence. Each node is composed of value and a pointer to the next node in the sequence. This structure allows for efficient insertion or removal of elements from any position in the sequence. Linked list are based on dynamically allocated nodes and this make it the simplest use case to test binwatch. The follwoing figure illustrates an output of binviz given a program implementing linked list structure.

![alt tag](https://github.com/maroueneboubakri/binviz/blob/master/linked_list.png)


## Authors
- Marouene Boubakri <[marouene.boubakri@eurecom.fr](mailto:marouene.boubakri@eurecom.fr)>
