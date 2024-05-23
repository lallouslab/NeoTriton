//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#pragma once

#include <map>
#include <memory>
#include <ostream>
#include <string>
#include <unordered_map>

#include <triton/ast.hpp>
#include <triton/dllexport.hpp>

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

  //! The AST namespace
namespace triton::ast
{
   // Converts a Triton's AST to LVM IR.
  class TritonToLLVM 
  {
  private:
    //! The LLVM context.
    llvm::LLVMContext& llvmContext;

    //! The LLVM module.
    std::shared_ptr<llvm::Module> llvmModule;

    //! The LLVM IR builder.
    llvm::IRBuilder<> llvmIR;

    //! Map Triton variables to LLVM ones.
    std::map<triton::ast::SharedAbstractNode, llvm::Value*> llvmVars;

    //! Create a LLVM function. `fname` represents the name of the LLVM function.
    void createFunction(const triton::ast::SharedAbstractNode& node, const char* fname);

    //! Converts Triton AST to LLVM IR.
    llvm::Value* do_convert(const triton::ast::SharedAbstractNode& node, std::unordered_map<triton::ast::SharedAbstractNode, llvm::Value*>* results);

  public:
    //! Constructor.
    TRITON_EXPORT TritonToLLVM(llvm::LLVMContext& llvmContext);

    //! Lifts a symbolic expression and all its references to LLVM format. `fname` represents the name of the LLVM function.
    TRITON_EXPORT std::shared_ptr<llvm::Module> convert(const triton::ast::SharedAbstractNode& node, const char* fname = "__triton", bool optimize = false);
  };
}
