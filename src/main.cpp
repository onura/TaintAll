//
//  main.c
//  TaintAll
//
//  Created by Onur on 09/12/15.
//  Copyright © 2015 taintall. All rights reserved.
//

#include "Tainter.hpp"
#include "Instrumenter.hpp"
#include <iostream>


using namespace std;



int main(int argc, char * argv[]) {
    Tainter tainter;
    Instrumenter instrumenter;

    //cmd arguments
    instrumenter.init(argc, argv);
    
    instrumenter.runProgram();
    instrumenter.clean();
    
    return 0;
}
