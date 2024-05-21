//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#pragma once

#include <iostream>

#include <triton/ast.hpp>
#include <triton/dllexport.hpp>

//! The Representations namespace
namespace triton::ast::representations 
{
/*!
  *  \ingroup ast
  *  \addtogroup representations
  *  @{
  */

  /*!
    *  \interface AstRepresentationInterface
    *  \brief The AST representation interface.
    */
  class AstRepresentationInterface 
  {
    public:
      //! Constructor.
      TRITON_EXPORT virtual ~AstRepresentationInterface(){};
      //! Entry point of print.
      TRITON_EXPORT virtual std::ostream& print(std::ostream& stream, triton::ast::AbstractNode* node) = 0;
  };

/*! @} End of representations namespace */
};
