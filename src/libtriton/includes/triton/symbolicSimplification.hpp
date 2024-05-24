//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#pragma once

#include <triton/architecture.hpp>
#include <triton/ast.hpp>
#include <triton/basicBlock.hpp>
#include <triton/callbacks.hpp>
#include <triton/dllexport.hpp>

namespace triton::engines::symbolic 
{
  //! \class SymbolicSimplification
  /*! \brief The symbolic simplification class */
  class SymbolicSimplification 
  {
    private:
      //! Architecture context
      triton::arch::Architecture* architecture;

      //! Callbacks API
      triton::callbacks::Callbacks* callbacks;

      //! Copies a SymbolicSimplification.
      void copy(const SymbolicSimplification& other);

      //! Performs a dead store elimination analysis.
      triton::arch::BasicBlock deadStoreElimination(const triton::arch::BasicBlock& block, bool padding=false) const;

    public:
      //! Constructor.
      TRITON_EXPORT SymbolicSimplification(triton::arch::Architecture* architecture, triton::callbacks::Callbacks* callbacks=nullptr);

      //! Constructor.
      TRITON_EXPORT SymbolicSimplification(const SymbolicSimplification& other);

      //! Processes all recorded simplifications. Returns the simplified node.
      TRITON_EXPORT triton::ast::SharedAbstractNode simplify(const triton::ast::SharedAbstractNode& node) const;

      //! Performs a dead store elimination simplification. If `padding` is true, keep addresses aligned and padds with NOP instructions.
      TRITON_EXPORT triton::arch::BasicBlock simplify(const triton::arch::BasicBlock& block, bool padding=false) const;

      //! Copies a SymbolicSimplification.
      TRITON_EXPORT SymbolicSimplification& operator=(const SymbolicSimplification& other);
  };

/*! @} End of symbolic namespace */
}
