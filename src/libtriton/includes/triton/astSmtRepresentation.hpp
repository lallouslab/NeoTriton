//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/


#pragma once

#include <iostream>

#include <triton/astRepresentationInterface.hpp>
#include <triton/ast.hpp>
#include <triton/dllexport.hpp>

// The Representations namespace
namespace triton::ast::representations 
{
  // SMT representation.
  class AstSmtRepresentation : public AstRepresentationInterface 
  {
    public:
      TRITON_EXPORT AstSmtRepresentation();
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::AbstractNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::ArrayNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::AssertNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BswapNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvaddNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvandNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvashrNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvlshrNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvmulNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvnandNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvnegNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvnorNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvnotNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvorNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvrolNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvrorNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvsdivNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvsgeNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvsgtNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvshlNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvsleNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvsltNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvsmodNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvsremNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvsubNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvudivNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvugeNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvugtNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvuleNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvultNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvuremNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvxnorNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::BvxorNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::CompoundNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::ConcatNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::DeclareNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::DistinctNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::EqualNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::ExtractNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::ForallNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::IffNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::IntegerNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::IteNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::LandNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::LetNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::LnotNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::LorNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::LxorNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::ReferenceNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::SelectNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::StoreNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::StringNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::SxNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::VariableNode* node);
      TRITON_EXPORT std::ostream& print(std::ostream& stream, triton::ast::ZxNode* node);
  };
}
