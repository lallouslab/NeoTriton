//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#pragma once

#include <iostream>
#include <memory>

#include <triton/ast.hpp>
#include <triton/astEnums.hpp>
#include <triton/astRepresentationInterface.hpp>
#include <triton/dllexport.hpp>

// The AST namespace
namespace triton::ast 
{
  // The Representations namespace
  namespace representations 
  {
    // Pseudo code of SMT AST.
    class AstRepresentation 
    {
      protected:
        //! The representation mode.
        triton::ast::representations::mode_e mode;

        // AstRepresentation interface.
        std::unique_ptr<triton::ast::representations::AstRepresentationInterface> representations[triton::ast::representations::LAST_REPRESENTATION];

      public:
        TRITON_EXPORT AstRepresentation();
        TRITON_EXPORT AstRepresentation(const AstRepresentation& other);
        TRITON_EXPORT AstRepresentation& operator=(const AstRepresentation& other);
        TRITON_EXPORT triton::ast::representations::mode_e getMode(void) const;
        TRITON_EXPORT void setMode(triton::ast::representations::mode_e mode);
        TRITON_EXPORT std::ostream& print(std::ostream& stream, AbstractNode* node);
    };
  };
};
