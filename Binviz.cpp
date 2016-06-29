/* ---------------------------------------------------------------------------
** Binviz is a dynamic memory changes monitoring tool. 
** It enables the dynamic data collection from a running process to the analysis and data representation. 
** The tool has capability to assist reverse engineers in analyzing and comprehending dynamic memory evolution and to detect patterns, and outliers that are not obvious using non graphical forms of presentation. 
** Binviz is based on binary instrumentation. 
** Given a binary executable, binwatch executes the binary in top of a dynamic binary instrumentation framework, monitors the execution, collect changes on memory objects, and finally produce a graph illustrating observed memory objects and their evolution during the execution.
**
** Binviz.cpp
**  
**
** Author: Marouene Boubakri <marouene.boubakri@eurecom.fr>
** -------------------------------------------------------------------------*/

/*



*/
#include "pin.H"
#include <asm/unistd.h>
#include <iostream>
#include <fstream>
#include <list>
#include <map>
#include <vector>
#include <ctime>
#include <iomanip>
#include <string>
#include <sstream>
#include <algorithm>
#include <iterator>

//Drawing Lib 

#include <ogdf/basic/Graph.h>
#include <ogdf/basic/graph_generators.h>
#include <ogdf/fileformats/GraphIO.h>

#include <ogdf/cluster/ClusterGraph.h>
#include <ogdf/cluster/ClusterPlanarizationLayout.h>

#include <ogdf/layered/SugiyamaLayout.h>
#include <ogdf/layered/OptimalRanking.h>
#include <ogdf/layered/MedianHeuristic.h>
#include <ogdf/layered/OptimalHierarchyLayout.h>
#include <ogdf/layered/BarycenterHeuristic.h>
#include <ogdf/layered/OptimalHierarchyClusterLayout.h>

using namespace std;
using namespace ogdf;


typedef struct _tag_ImgAddr{
  ADDRINT low;
  ADDRINT high;
}IMG_ADDR, *PIMG_ADDR;

IMG_ADDR MAIN_IMG = { 0 };

/* ===================================================================== */
/*  Memory operations related variable and data structure                */
/* ===================================================================== */
#define MEM_OP_READ 1
#define MEM_OP_WRITE  2
#define MEM_OP_ALLOC  3
#define MEM_OP_FREE   4

//const string MEM_OP[] = {"Read", "Write", "Alloc", "Free"};
const string MEM_OP[] = {"U", "R", "W", "A", "F"};

struct MemoryOperation
{
  UINT64 base;
  UINT64 size;
  UINT64 op;
  UINT64 insAdd;
  UINT64 order;
  string insDis;
  string dump;
  BOOL stackOp;
};

typedef std::map<ADDRINT, std::vector<struct MemoryOperation> > ObjectMemoryOperation;

VOID *lastEA = NULL;

/* ===================================================================== */
/*  Observation points variables                                         */
/* ===================================================================== */

std::vector<ADDRINT>    observationPoints;

struct ObservationRange
{
  ADDRINT start;
  ADDRINT end;
  //bool operator<(const ObservationRange& obRng) const;
};
bool operator<(const ObservationRange& l, const ObservationRange& r )
{
  return ( l.start != r.start ) || ( l.end != r.end);
}

UINT64 operationCounter = 1;
typedef std::map<struct ObservationRange, std::map<ADDRINT, std::vector<struct MemoryOperation> > > MemoryOperationMap;
MemoryOperationMap memoryOperationMap;

/* ===================================================================== */
/*  Variables used to holds dynamically allocated memory */
/* ===================================================================== */

#define ALLOCATE  1
#define FREE      !ALLOCATE
static size_t         lastAllocSize;
struct MallocArea
{
  UINT64  base;
  UINT64  size;
  BOOL    status;
};
std::list<struct MallocArea>    mallocAreaList;

/* ===================================================================== */
/* Data structure used holds mapped memory sections of the binary          */
/* ===================================================================== */
struct MemorySection
{
  ADDRINT base;
  UINT64 size;
  string name;
  string type;
};
std::list<struct MemorySection>    memorySectionList;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<BOOL>   KnobResolvePointer(KNOB_MODE_WRITEONCE, "pintool", "pointer", "0", "Resolve pointers");
KNOB<BOOL>   KnobWatchStatic(KNOB_MODE_WRITEONCE, "pintool", "static", "0", "Include operations on static memory");
KNOB<string> KnobObservationPoints(KNOB_MODE_WRITEONCE, "pintool", "opset", "0", "The observation points");
KNOB<BOOL>   KnobTraceExec(KNOB_MODE_WRITEONCE, "pintool", "trace", "0", "Trace the executed instructions");
KNOB<BOOL>   KnobListSections(KNOB_MODE_WRITEONCE, "pintool", "mapping", "0", "List all mapped memory regions");
KNOB<BOOL>   KnobDumpMemory(KNOB_MODE_WRITEONCE, "pintool", "dump", "0", "Dump process memory at supplied observations points");

string invalid = "invalid_rtn";

/* ===================================================================== */
/*  Functions                                                            */
/* ===================================================================== */
INT32 Usage()
{
  cerr << "This tool produces a call trace." << endl << endl;
  cerr << KNOB_BASE::StringKnobSummary() << endl;
  return -1;
}


VOID DumpMemoryToFile(string fileName)
{
  ofstream dumpFile;
  dumpFile.open (fileName.c_str(), ios::binary | ios::out);
  dumpFile.write((CHAR*)MAIN_IMG.low, MAIN_IMG.high - MAIN_IMG.low);
  dumpFile.close();
}

VOID SummarizeChanges()
{

  for(MemoryOperationMap::iterator mmIt = memoryOperationMap.begin(); mmIt != memoryOperationMap.end(); ++mmIt)
  {

    cout<<endl;    
    cout<<"Memory operations summary of observation region ("
      <<hex<< mmIt->first.start << "-" 
      << hex<< mmIt->first.end
      << ")"<< endl;

    ObjectMemoryOperation memOps = mmIt->second;

    std::cout << std::string(80, '-') << endl;
    cout << std::left << std::setw(16) << std::setfill(' ') << "Address";
    cout << std::left << std::setw(16) << std::setfill(' ') << "Operation";
    cout << std::left << std::setw(16) << std::setfill(' ') << "Value";
    cout << std::left << std::setw(16) << std::setfill(' ') << "Instruction";
    cout << std::left << std::setw(16) << std::setfill(' ') << "Order";
    cout << endl;
    std::cout << std::string(80, '-') << endl;


    for ( ObjectMemoryOperation::iterator memOpIt = memOps.begin(); memOpIt != memOps.end(); memOpIt++)
    {

      cout << std::left << std::setw(16) << std::setfill(' ') << std::hex << memOpIt->first<<endl;      

      for(std::vector<int>::size_type i = 0; i != memOpIt->second.size(); i++) {

        cout << std::left << std::setw(16) << std::setfill(' ') << "";
        cout << std::left << std::setw(16) << std::setfill(' ') << MEM_OP[memOpIt->second[i].op] ;

        if(memOpIt->second[i].op == MEM_OP_READ || memOpIt->second[i].op == MEM_OP_WRITE)
        {
          cout << std::left << std::setw(16) << std::setfill(' ') << memOpIt->second[i].dump;
          cout << std::left << std::setw(16) << std::setfill(' ') << std::hex<<memOpIt->second[i].insAdd;
        }

        else if(memOpIt->second[i].op == MEM_OP_ALLOC)
        {
          cout << std::left << std::setw(16) << std::setfill(' ')<< memOpIt->second[i].size;
          cout << std::left << std::setw(16) << std::setfill(' ')<< "malloc()";
        }

        else if(memOpIt->second[i].op == MEM_OP_FREE)
        {
          cout << std::left << std::setw(16) << std::setfill(' ')<< memOpIt->second[i].size;;
          cout << std::left << std::setw(16) << std::setfill(' ')<< "free()";  
        }
    //cout<<std::resetiosflags(std::cout.flags());
        std::ostringstream oss;
        oss<<"["<<memOpIt->second[i].order<<"]";
        cout << std::left << std::setw(16) << std::setfill(' ')<< flush << oss.str();
        cout<<endl;
    //std::cout << "\t\t" << memOpIt->second[i].insDis << endl;  
      }

    }
  } 

}

VOID GenerateGraph()
{

  for(MemoryOperationMap::iterator momIt = memoryOperationMap.begin(); momIt != memoryOperationMap.end(); momIt++)
    {

  Graph G;
  ClusterGraph CG(G);
  ClusterGraphAttributes CGA( CG ,ClusterGraphAttributes::nodeGraphics |
    ClusterGraphAttributes::edgeGraphics |
    ClusterGraphAttributes::nodeLabel |
    ClusterGraphAttributes::nodeStyle |
    ClusterGraphAttributes::edgeType |
    ClusterGraphAttributes::edgeArrow |
    ClusterGraphAttributes::edgeLabel |
    ClusterGraphAttributes::edgeStyle); 

    ObjectMemoryOperation memOps = momIt->second;
     
      for ( ObjectMemoryOperation::reverse_iterator  memOprIt = memOps.rbegin(); memOprIt != memOps.rend(); memOprIt++)
      {            
        BOOL includeObj = TRUE;

        if(!KnobWatchStatic.Value())
        {
            includeObj = FALSE;
            for(list<struct MallocArea>::iterator maIt = mallocAreaList.begin(); maIt != mallocAreaList.end(); maIt++)           
              {                 ADDRINT objAddr = memOprIt->first; 

                if((objAddr >= maIt->base) 
                  /*&& ((maIt->base + maIt->size)>= objAddr)*/
                  )
                  includeObj = TRUE; break;                  
              }
        }            
        if(!includeObj)
          continue;

       std::stringstream stream;
       stream << std::hex << memOprIt->first;

       node memObNode = G.newNode();

       CGA.height( memObNode ) = 20.0; 
       CGA.width( memObNode ) = 70.0; 

       CGA.label( memObNode ) = stream.str().c_str();

       for(std::vector<int>::size_type i =memOprIt->second.size(); i-->0 ;) {

        node memInsNode = G.newNode();
        node memValNode = G.newNode();

        CGA.height( memInsNode ) = 20.0; 
        CGA.width( memInsNode ) = 80.0; 

        CGA.height( memValNode ) = 20.0; 
        CGA.width( memValNode ) = 60.0; 

        CGA.fillColor( memValNode ) = Color( "#FFFF00" );
        CGA.shape(memValNode) = ogdf::shEllipse;

        std::stringstream stream;
        stream << std::hex << memOprIt->second[i].insAdd;
        stream<<std::resetiosflags(std::cout.flags());
        stream << " [" << memOprIt->second[i].order << "]";
        CGA.label( memInsNode ) = memOprIt->second[i].insAdd == 0 ? memOprIt->second[i].insDis : stream.str().c_str();

        stream.str( std::string() );
        stream.clear();
        stream<< MEM_OP[memOprIt->second[i].op] << " ";
        if(memOprIt->second[i].op == MEM_OP_ALLOC)
          stream << memOprIt->second[i].size;  
        else if(memOprIt->second[i].op == MEM_OP_READ || memOprIt->second[i].op == MEM_OP_WRITE)
          stream << memOprIt->second[i].dump;
        CGA.label( memValNode ) = stream.str();

        edge e1 =G.newEdge(memInsNode, memValNode);
        CGA.arrowType(e1) = ogdf::eaNone;
        edge e2 =G.newEdge(memValNode, memObNode);
        CGA.arrowType(e2) = ogdf::eaLast;
      }

  }//end for each allocated area 

node v1;
for(list<struct MallocArea>::reverse_iterator ri = mallocAreaList.rbegin(); ri != mallocAreaList.rend(); ri++){   
      //cluster c = CG.newCluster(CG.rootCluster());
  ogdf::SList<node> clusterNodes;

  forall_nodes( v1, G ){
    ADDRINT addr = AddrintFromString(CGA.label(v1));
    if((addr != 0 ) && (addr >= ri->base && addr <= (ri->base + ri->size)))
    {
      //CG.reassignNode(v1, c);
     clusterNodes.pushFront(v1);
     }
 }   
 if(clusterNodes.size() > 0)
 {
  cluster c = CG.createCluster(clusterNodes);
  CGA.strokeWidth(c) = 2;
  CGA.strokeColor(c) = ogdf::Color::Black;
 }
}

//resolve pointer
if(KnobResolvePointer.Value())
{
 node v1, v2;
 forall_nodes( v1, G ){ 
    //cout<< "[v1] " <<GA.label(v1) <<endl;
  for ( ObjectMemoryOperation::iterator memOpIt = memOps.begin(); memOpIt != memOps.end(); memOpIt++)     
  {
    std::stringstream stream;
    stream << std::hex << memOpIt->first;
    if(stream.str() == CGA.label(v1))
    {
      forall_nodes( v2, G ){        
        for(std::vector<int>::size_type i = 0; i != memOpIt->second.size(); i++) {
                  //cout<<"[V1] " << CGA.label(v1) << " [V2]" << CGA.label(v2)  << endl;
          if(memOpIt->second[i].dump == CGA.label(v2))
          {
                    //cout<<"[POINTER] " << memOpIt->second[i].dump << " " << CGA.label(v2)  << endl;
            edge e = G.newEdge(v1, v2);
            CGA.setStrokeType(e, ogdf::stDot);
            break;
          }
        }
      }
    }
  }
}
}  

SugiyamaLayout SL;

SL.setRanking(new OptimalRanking);
SL.setCrossMin(new BarycenterHeuristic);

OptimalHierarchyClusterLayout *ohl = new OptimalHierarchyClusterLayout;
    ohl->layerDistance(10.0);    // set layer distance to 40.0 
    ohl->nodeDistance(10.0); // set node distance to 20.0.

    SL.setClusterLayout(ohl);
    SL.call(CGA);

        std::stringstream stream;
        stream << "graph_"<<std::hex<< momIt->first.start << "_" <<momIt->first.end << ".svg";
        cout<<"Wrting Graph to "<<stream.str().c_str()<<" file"<<endl;
    GraphIO::drawSVG( CGA, stream.str().c_str());    

}//end for each observation point

}


VOID ListMemorySections()
{

  list<struct MemorySection>::iterator i;
  std::cout << std::string(64, '-') << endl;
  cout << std::left << std::setw(16) << std::setfill(' ') << "Start";
  cout << std::left << std::setw(8) << std::setfill(' ') << "Size";
  cout << std::left << std::setw(16) << std::setfill(' ') << "Name";
  cout << std::left << std::setw(8) << std::setfill(' ') << "Type";
  cout << endl;
  std::cout << std::string(64, '-') << endl;

  for(i = memorySectionList.begin(); i != memorySectionList.end(); i++){

    std::ostringstream oss;
    oss<<hex<< i->base << "-" << hex<< (i->base + i->size);

    cout << std::left << std::setw(16) << std::setfill(' ') << oss.str();
    cout << std::left << std::setw(8) << std::setfill(' ')  << hex << i->size;
    cout << std::left << std::setw(16) << std::setfill(' ') << i->name;
    cout << std::left << std::setw(8) << std::setfill(' ')  << i->type;
    cout << endl;
  }

}


VOID RecordMemoryOperation(UINT64 base, UINT64 size, UINT64 op, ADDRINT insAdd, string insDis, string dump, BOOL stackOp){


   //check at which observation range instruction belongs to
   //create it if does not exist
  struct MemoryOperation memop;
  memop.size = size;
  memop.base = base;
  memop.op = op;
  memop.insAdd = insAdd;
  memop.insDis = insDis;
  memop.dump = dump;
  memop.stackOp = stackOp;
  memop.order = operationCounter++;
  //memOps[base].push_back(memop);


  for(vector<ADDRINT>::iterator obIt = observationPoints.begin(); obIt< observationPoints.end(); obIt+=2)
  {
    ADDRINT obPt1 = *obIt != 0 ? *obIt: MAIN_IMG.low;
    ADDRINT obPt2 = *(obIt+1) != 0 ? *(obIt+1) : MAIN_IMG.high;

//     printf("%x in range(%x-%x) ? \n", insAdd, obPt1, obPt2);

    if(insAdd >= obPt1 && insAdd <= obPt2)
    {

     //printf("Adding one object\n");
      struct ObservationRange obRange;
      obRange.start = obPt1;
      obRange.end = obPt2;    
      memoryOperationMap[obRange][base].push_back(memop);
    }
    
  }



}

/* ===================================================================== */
const string *Target2String(ADDRINT target)
{
  string name = RTN_FindNameByAddress(target);
  if (name == "")
    return &invalid;
  else
    return new string(name);
}

/* ===================================================================== */

VOID  DoCallArgs(const string *s, ADDRINT target, ADDRINT arg0)
{


}

/* ===================================================================== */

VOID  DoCallArgsIndirect(ADDRINT target, BOOL taken, ADDRINT arg0)
{
  if( !taken ) return;

  const string *s = Target2String(target);
  DoCallArgs(s, target, arg0);

  if (s != &invalid)
    delete s;
}

/* ===================================================================== */

VOID  DoCall(const string *s)
{
  
}

/* ===================================================================== */

VOID  DoCallIndirect(ADDRINT target, BOOL taken)
{
  if( !taken ) return;

  const string *s = Target2String(target);
  DoCall( s );

  if (s != &invalid)
    delete s;
}

VOID CallbackBeforeMalloc(ADDRINT size)
{
  lastAllocSize = size;
}

VOID CallbackBeforeFree(ADDRINT addr, ADDRINT retAddr)
{ 
  list<struct MallocArea>::iterator i;
  
  RecordMemoryOperation(addr, 0, MEM_OP_FREE, retAddr, "free()", "0", FALSE);
  for(i = mallocAreaList.begin(); i != mallocAreaList.end(); i++){
    if (addr == i->base){
      i->status = FREE;      
      break;
    }
  }
}


VOID CallbackAfterFree(ADDRINT addr, ADDRINT retAddr)
{
}

VOID CallbackAfterMalloc(ADDRINT addr, ADDRINT retAddr)
{

  if((addr & 0xb0000000) == 0xb0000000)
    return; 

  list<struct MallocArea>::iterator i;
  struct MallocArea allocArea;

  if (addr){

    RecordMemoryOperation((UINT64)addr, lastAllocSize, MEM_OP_ALLOC, retAddr, "malloc()", "0", FALSE);

    for(i = mallocAreaList.begin(); i != mallocAreaList.end(); i++){
      if (addr == i->base){
        i->status = ALLOCATE;
        i->size = lastAllocSize;
        return;
      }
    }
    
    allocArea.base = addr;
    allocArea.size = lastAllocSize;
    allocArea.status = ALLOCATE;

    mallocAreaList.push_back(allocArea);  
  }

}

VOID Image(IMG img, VOID *v)
{

 string img_type;
 string sec_type;

 if (IMG_IsMainExecutable(img)){
  MAIN_IMG.low = IMG_LowAddress(img);
  MAIN_IMG.high = IMG_HighAddress(img);  
}

if(KnobObservationPoints.Value().empty())
{
  observationPoints.push_back(MAIN_IMG.low);
  observationPoints.push_back(MAIN_IMG.high);
}

switch (IMG_Type(img)){
  case IMG_TYPE_STATIC:
  img_type = "static";
  break;
  case IMG_TYPE_SHARED:
  img_type = "shared";
  break;
  case IMG_TYPE_SHAREDLIB:
  img_type = "shared library";
  break;
  case IMG_TYPE_RELOCATABLE:
  img_type = "relocatable";
  break;
  default:
  img_type = "unknown";
}

    /*cout << "[IMG] Loading image " << IMG_Name(img).c_str();
    cout << " @ " << StringFromAddrint(IMG_StartAddress(img));
    cout << " type " << img_type << endl;
*/
    if(IMG_IsMainExecutable(img))   
     for (SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec=SEC_Next(sec)) {


       if (strcmp(SEC_Name(sec).c_str(),"")) {

        switch (SEC_Type(sec)){
          case SEC_TYPE_REGREL:
          sec_type = "relocations";
          break;
          case SEC_TYPE_DYNREL:
          sec_type = "dynamic relocations";
          break;
          case SEC_TYPE_EXEC:
          sec_type = "code";
          break;
          case SEC_TYPE_DATA:
          sec_type = "data";
          break;
          case SEC_TYPE_BSS:
          sec_type = "bss";
          break;
          case SEC_TYPE_LOOS:
          sec_type = "operating system specific";
          break;
          case SEC_TYPE_USER:
          sec_type = "user application specific";
          break;
          default:
          sec_type = "unknown";
        }

        struct MemorySection section;

        section.base = SEC_Address(sec);
        section.size = SEC_Size(sec);
        section.name = SEC_Name(sec).c_str();
        section.type = sec_type;
        memorySectionList.push_back(section);
      }
    }

//dumpSections();
  //cout<<"IMG loaded\t\t\t\t\t"<<IMG_Name(img)<<endl;
    RTN mallocRtn = RTN_FindByName(img, "malloc");
    RTN freeRtn = RTN_FindByName(img, "free");

    if (RTN_Valid(mallocRtn)){
      RTN_Open(mallocRtn);

      RTN_InsertCall(
        mallocRtn, 
        IPOINT_BEFORE, (AFUNPTR)CallbackBeforeMalloc,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_END);

      RTN_InsertCall(
        mallocRtn, 
        IPOINT_AFTER, (AFUNPTR)CallbackAfterMalloc,
        IARG_FUNCRET_EXITPOINT_VALUE, 
        IARG_RETURN_IP,
        IARG_END);

      RTN_Close(mallocRtn);
    }

    if (RTN_Valid(freeRtn)){
      RTN_Open(freeRtn);
      RTN_InsertCall(
        freeRtn, 
        IPOINT_BEFORE, (AFUNPTR)CallbackBeforeFree,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_RETURN_IP,
        IARG_END);

   /* RTN_InsertCall(
    freeRtn, 
    IPOINT_AFTER, (AFUNPTR)CallbackAfterFree,
    IARG_FUNCRET_EXITPOINT_VALUE, 0,
    IARG_RETURN_IP,
    IARG_END);*/


    RTN_Close(freeRtn);
  }
}



/* ===================================================================== */

VOID Trace(TRACE trace, VOID *v)
{
    const BOOL print_args = true; //KnobPrintArgs.Value();
    

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
      INS tail = BBL_InsTail(bbl);

      if( INS_IsCall(tail) )
      {
        if( INS_IsDirectBranchOrCall(tail) )
        {
          const ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);
          if( print_args )
          {
            INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(DoCallArgs),
             IARG_PTR, Target2String(target), IARG_G_ARG0_CALLER, IARG_END);
          }
          else
          {
            INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(DoCall),
             IARG_PTR, Target2String(target), IARG_END);
          }

        }
        else
        {
          if( print_args )
          {
            INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(DoCallArgsIndirect),
             IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_G_ARG0_CALLER, IARG_END);
          }
          else
          {
            INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(DoCallIndirect),
             IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
          }


        }
      }
      else
      {
            // sometimes code is not in an image
       RTN rtn = TRACE_Rtn(trace);

            // also track stup jumps into share libraries
       if( RTN_Valid(rtn) && !INS_IsDirectBranchOrCall(tail) && ".plt" == SEC_Name( RTN_Sec( rtn ) ))
       {
        if( print_args )
        {
          INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(DoCallArgsIndirect),
           IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_G_ARG0_CALLER, IARG_END);
        }
        else
        {
          INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(DoCallIndirect),
           IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);

        }
      }
    }

  }
}
/*
static VOID StackRead(ADDRINT ins, VOID * addr, INT32 size)
{
 //  cout<<"[stack-read\t  " << size <<" in " <<addr << "] : "<<ins<< endl;
}
*/

static VOID MemoryReadWrite(ADDRINT ins, std::string insDis, VOID * addr, INT32 size, INT32 memReadWrite, BOOL isStackReadWrite, INT32 insPoint)
{

  if(insPoint == IPOINT_BEFORE)
    lastEA = addr;
  if(insPoint == IPOINT_AFTER)
    addr = lastEA;

  if (ins >= MAIN_IMG.low && ins < MAIN_IMG.high){

   //cout<<"[R/W\t  " << size <<" in " <<addr <<"("<< *((int*)addr)<<")"<< "] 0x"<<std::hex<<ins<< " " << insDis<<endl;

    string dump;
    std::stringstream stream;

    switch(size)
    {

      case sizeof(int):
      stream << std::hex << *((int*)addr);
      break;

  /*case sizeof(long):
  stream << std::hex << *((long*)addr);
  break;

  case sizeof(short):
  stream << std::hex << *((short*)addr);
  break;*/

  case sizeof(char):
  if(std::isalpha(*((char*)addr)) || std::isdigit(*((char*)addr)))
    stream << "'"<<*((char*)addr)<<"'";
  else
    stream <<"0x"<< std::hex << (unsigned int)*((char*)addr);
  break;

  default:
  for(int i=0; i <size; i++)
    stream << std::hex << *((char*)addr);
  break;
}

dump = stream.str();

if(insPoint == IPOINT_AFTER)
  RecordMemoryOperation((UINT64)addr, size, memReadWrite, ins, insDis, dump, isStackReadWrite);

}
}

VOID insCallBack(ADDRINT insAdd, std::string insDis, CONTEXT *ctx, ADDRINT nextInsAdd)
{

  if(KnobTraceExec.Value())
    cout<< std::hex << insAdd << ": " <<insDis<<endl;
   //Check if EIP is in supplied observations points and dump memory if so
  if(KnobDumpMemory.Value())
   if(std::find(observationPoints.begin(), observationPoints.end(), insAdd) != observationPoints.end()) {   
     std::stringstream s;
   //Time added to avoid overide dump in case of a loop
     s << "dump_" <<hex<<insAdd <<"_"<<hex<<std::time(0);
     cout << "[Dump] at 0x"  << hex<<insAdd<<" to " << s.str() << endl;
     DumpMemoryToFile(s.str());
   }

 }

 VOID Instruction(INS ins, VOID *v)
 {

  PIN_LockClient();
  IMG img = IMG_FindByAddress(INS_Address(ins));
  PIN_UnlockClient();

  if (IMG_Valid(img) && IMG_IsMainExecutable(img)){
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)insCallBack,
     IARG_ADDRINT, INS_Address(ins),
     IARG_PTR, new string(INS_Disassemble(ins)),
     IARG_CONTEXT,
     IARG_ADDRINT, INS_NextAddress(ins),
     IARG_END);
  }


  BOOL isStackReadWrite = INS_IsStackRead(ins) || INS_IsStackWrite(ins);

  UINT32 isMemoryReadWrite = 0;
  UINT32 iargMemoryAddress = 0;
  UINT32 iargMemorySize = 0;

if(/*INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0) && !INS_IsCall(ins)*/INS_IsMemoryRead(ins))
  {
    isMemoryReadWrite = MEM_OP_READ;
    iargMemoryAddress = IARG_MEMORYREAD_EA;
    iargMemorySize = IARG_MEMORYREAD_SIZE;
  }
  else  if(INS_IsMemoryWrite(ins))
  {
    isMemoryReadWrite = MEM_OP_WRITE;
    iargMemoryAddress = IARG_MEMORYWRITE_EA;
    iargMemorySize = IARG_MEMORYWRITE_SIZE;
  }

  if(INS_IsOriginal(ins) && (isMemoryReadWrite == MEM_OP_READ || isMemoryReadWrite == MEM_OP_WRITE))
  {

   INS_InsertPredicatedCall(
    ins, IPOINT_BEFORE, (AFUNPTR)MemoryReadWrite,
    IARG_INST_PTR, 
    IARG_PTR, new string(INS_Disassemble(ins)),
    iargMemoryAddress,
    iargMemorySize,
    IARG_UINT32, isMemoryReadWrite,
    IARG_BOOL, isStackReadWrite,
    IARG_UINT32, IPOINT_BEFORE,
    IARG_END);

   if(!isStackReadWrite && INS_HasFallThrough(ins))
     INS_InsertPredicatedCall(
      ins, IPOINT_AFTER, (AFUNPTR)MemoryReadWrite,
      IARG_INST_PTR, 
      IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, NULL,
      iargMemorySize,
      IARG_UINT32, isMemoryReadWrite,
      IARG_BOOL, isStackReadWrite,
      IARG_UINT32, IPOINT_AFTER,
      IARG_END);

 }


//insert callback


}

VOID Syscall(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{

}




/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
  if(KnobListSections.Value())
    ListMemorySections();
  SummarizeChanges();
  GenerateGraph();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int  main(int argc, char *argv[])
{

  PIN_InitSymbols();

  if( PIN_Init(argc,argv) )
  {
    return Usage();
  }
  
  if(!KnobObservationPoints.Value().empty())
  {
  string obPt; 
  stringstream ss(KnobObservationPoints.Value()); 
  while (ss >> obPt)
    observationPoints.push_back(AddrintFromString(obPt));
  }

  PIN_AddSyscallEntryFunction(Syscall, 0);
  INS_AddInstrumentFunction(Instruction, 0);
  TRACE_AddInstrumentFunction(Trace, 0);
  IMG_AddInstrumentFunction(Image, 0);
  PIN_AddFiniFunction(Fini, 0);

    // Never returns

  PIN_StartProgram();

  return 0;
}

/* ===================================================================== */
/* EOF */
/* ===================================================================== */
