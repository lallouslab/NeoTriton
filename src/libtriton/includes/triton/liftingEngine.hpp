//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#pragma once

#include <triton/astContext.hpp>
#include <triton/config.hpp>
#include <triton/dllexport.hpp>
#include <triton/liftingToDot.hpp>
#include <triton/liftingToPython.hpp>
#include <triton/liftingToSMT.hpp>
#include <triton/symbolicEngine.hpp>
#include <triton/symbolicExpression.hpp>

#ifdef TRITON_LLVM_INTERFACE
  #include <triton/liftingToLLVM.hpp>
#endif

namespace triton::engines::lifters
{
  //! \class LiftingEngine
  /*! \brief The lifting engine class. */
  class LiftingEngine : 
    public LiftingToSMT,
    public LiftingToDot,
#ifdef TRITON_LLVM_INTERFACE
    public LiftingToLLVM,
#endif
    public LiftingToPython
  {
  public:
    //! Constructor.
    TRITON_EXPORT LiftingEngine(const triton::ast::SharedAstContext& astCtxt, triton::engines::symbolic::SymbolicEngine* symbolic)
      : LiftingToSMT(astCtxt, symbolic),
      LiftingToDot(astCtxt, symbolic),
#ifdef TRITON_LLVM_INTERFACE
      LiftingToLLVM(),
#endif
      LiftingToPython(astCtxt, symbolic) {
    }
  };
}
