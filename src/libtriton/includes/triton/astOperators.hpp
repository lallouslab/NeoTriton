//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#pragma once

#include <deque>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <triton/astEnums.hpp>
#include <triton/coreUtils.hpp>
#include <triton/cpuSize.hpp>
#include <triton/dllexport.hpp>
#include <triton/exceptions.hpp>
#include <triton/tritonTypes.hpp>
#include <triton/context.hpp>

namespace triton::ast::operators
{
  // Wrapper class for AST nodes to enable natural operations
  class ASTNodeWrapper
  {
  public:
    triton::ast::SharedAbstractNode node;
    triton::ast::SharedAstContext ast;

    ASTNodeWrapper(const triton::ast::SharedAbstractNode& node, triton::ast::SharedAstContext ast)
      : node(node), ast(std::move(ast)) {}

    // Operator overloads for arithmetic operations
    ASTNodeWrapper operator+(const ASTNodeWrapper& other) const {
      return ASTNodeWrapper(ast->bvadd(this->node, other.node), this->ast);
    }

    ASTNodeWrapper operator-(const ASTNodeWrapper& other) const {
      return ASTNodeWrapper(ast->bvsub(this->node, other.node), this->ast);
    }

    ASTNodeWrapper operator*(const ASTNodeWrapper& other) const {
      return ASTNodeWrapper(ast->bvmul(this->node, other.node), this->ast);
    }

    ASTNodeWrapper operator/(const ASTNodeWrapper& other) const {
      return ASTNodeWrapper(ast->bvudiv(this->node, other.node), this->ast);
    }

    ASTNodeWrapper operator<<(const ASTNodeWrapper& other) const {
      return ASTNodeWrapper(ast->bvshl(this->node, other.node), this->ast);
    }

    friend std::ostream& operator<<(std::ostream& os, const ASTNodeWrapper& wrapper) {
      os << wrapper.node;
      return os;
    }
  };

  // Function to create symbolic variables and wrap them in ASTNodeWrapper
  ASTNodeWrapper symvar(triton::SharedContext& ctx, int size, const std::string& name)
  {
    auto ast = ctx->getAstContext();
    auto var = ctx->newSymbolicVariable(size, name);
    return ASTNodeWrapper(ast->variable(var), ast);
  }

  // Function to create symbolic variables and wrap them in ASTNodeWrapper
  ASTNodeWrapper integer(triton::SharedContext& ctx, triton::uint512 value, int size)
  {
    auto ast = ctx->getAstContext();
    auto var = ast->integer(value);
    var->setBitvectorSize(size);
    return ASTNodeWrapper(var, ast);
  }
}
