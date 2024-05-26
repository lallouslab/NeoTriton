//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#include <triton/exceptions.hpp>
#include <triton/cpuSize.hpp>
#include <triton/symbolicVariable.hpp>

namespace triton::engines::symbolic 
{
  SymbolicVariable::SymbolicVariable(
      triton::engines::symbolic::variable_e type,
      triton::uint64 origin,
      triton::usize id,
      triton::uint32 size,
      const std::string& alias) 
  {
    this->alias   = alias;
    this->comment = "";
    this->id      = id;
    this->name    = TRITON_SYMVAR_NAME + std::to_string(id);
    this->origin  = origin;
    this->size    = size;
    this->type    = type;

    if (this->size > triton::bitsize::max_supported)
      throw triton::exceptions::SymbolicVariable("SymbolicVariable::SymbolicVariable(): Size cannot be greater than triton::bitsize::max_supported.");

    if (this->size == 0)
      throw triton::exceptions::SymbolicVariable("SymbolicVariable::SymbolicVariable(): Size cannot be zero.");
  }

  SymbolicVariable::SymbolicVariable(const SymbolicVariable& other) 
  {
    this->alias   = other.alias;
    this->comment = other.comment;
    this->id      = other.id;
    this->name    = other.name;
    this->origin  = other.origin;
    this->size    = other.size;
    this->type    = other.type;
  }

  SymbolicVariable& SymbolicVariable::operator=(const SymbolicVariable& other) 
  {
    this->alias   = other.alias;
    this->comment = other.comment;
    this->id      = other.id;
    this->name    = other.name;
    this->origin  = other.origin;
    this->size    = other.size;
    this->type    = other.type;
    return *this;
  }

  std::ostream& operator<<(std::ostream& stream, const SymbolicVariable& symVar) 
  {
    if (symVar.getAlias().empty())
      stream << symVar.getName() << ":" << symVar.getSize();
    else
      stream << symVar.getAlias() << ":" << symVar.getSize();
    return stream;
  }

  std::ostream& operator<<(std::ostream& stream, const SymbolicVariable* symVar) 
  {
    stream << *symVar;
    return stream;
  }

  bool operator<(const SymbolicVariable& symvar1, const SymbolicVariable& symvar2) {
    return symvar1.getId() < symvar2.getId();
  }
}
