//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#pragma once

/*! Defines the default name of a symbolic variable. */
#define TRITON_SYMVAR_NAME "SymVar_"

namespace triton::engines::symbolic 
{
  //! Type of symbolic expressions.
  enum expression_e 
  {
    MEMORY_EXPRESSION,     //!< Assigned to a memory expression.
    REGISTER_EXPRESSION,   //!< Assigned to a register expression.
    VOLATILE_EXPRESSION,   //!< Assigned to a volatile expression.
  };

  //! Type of symbolic variable.
  enum variable_e 
  {
    MEMORY_VARIABLE,       //!< Variable assigned to a memory.
    REGISTER_VARIABLE,     //!< Variable assigned to a register.
    UNDEFINED_VARIABLE,    //!< Undefined assignment.
  };
}
