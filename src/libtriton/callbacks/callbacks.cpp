//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#include <triton/context.hpp>
#include <triton/callbacks.hpp>
#include <triton/exceptions.hpp>

namespace triton::callbacks 
{
  Callbacks::Callbacks(triton::Context& ctx) : ctx(ctx) 
  {
    this->defined   = false;
    this->mget      = false;
    this->mload     = false;
    this->mput      = false;
    this->mstore    = false;
  }

  void Callbacks::addCallback(
    triton::callbacks::callback_e kind, 
    getConcreteMemoryValueCallback cb) 
  {
    if (kind == triton::callbacks::GET_CONCRETE_MEMORY_VALUE)
    {
      this->getConcreteMemoryValueCallbacks.push_back(cb);
      this->defined = true;
    }
  }

  void Callbacks::addCallback(
    triton::callbacks::callback_e kind, 
    getConcreteRegisterValueCallback cb)
  {
    if (kind == triton::callbacks::GET_CONCRETE_REGISTER_VALUE)
    {
      this->getConcreteRegisterValueCallbacks.push_back(cb);
      this->defined = true;
    }
  }

  void Callbacks::addCallback(triton::callbacks::callback_e kind, setConcreteMemoryValueCallback cb)
  {
    if (kind == triton::callbacks::SET_CONCRETE_MEMORY_VALUE)
    {
      this->setConcreteMemoryValueCallbacks.push_back(cb);
      this->defined = true;
    }
  }

  void Callbacks::addCallback(triton::callbacks::callback_e kind, setConcreteRegisterValueCallback cb) 
  {
    if (kind == triton::callbacks::SET_CONCRETE_REGISTER_VALUE)
    {
      this->setConcreteRegisterValueCallbacks.push_back(cb);
      this->defined = true;
    }
  }

  void Callbacks::addCallback(triton::callbacks::callback_e kind, symbolicSimplificationCallback cb) 
  {
    if (kind == triton::callbacks::SYMBOLIC_SIMPLIFICATION)
    {
      this->symbolicSimplificationCallbacks.push_back(cb);
      this->defined = true;
    }
  }

  void Callbacks::clearCallbacks(void) 
  {
    this->getConcreteMemoryValueCallbacks.clear();
    this->getConcreteRegisterValueCallbacks.clear();
    this->setConcreteMemoryValueCallbacks.clear();
    this->setConcreteRegisterValueCallbacks.clear();
    this->symbolicSimplificationCallbacks.clear();
    this->defined = false;
  }

  template <typename T>
  void Callbacks::removeSingleCallback(std::list<T>& container, T cb) 
  {
    for (auto it = container.begin(); it != container.end(); ++it) 
    {
      if (cb == *it) 
      {
        container.erase(it);
        return;
      }
    }
    throw triton::exceptions::Exception("Unable to find callback for removal");
  }

  void Callbacks::removeCallback(triton::callbacks::callback_e kind, getConcreteMemoryValueCallback cb)
  {
    if (kind == triton::callbacks::GET_CONCRETE_MEMORY_VALUE)
      this->removeSingleCallback(this->getConcreteMemoryValueCallbacks, cb);
    else
        throw triton::exceptions::Exception("Incorrect callback kind for removal");

    if (this->countCallbacks() == 0)
      this->defined = false;
  }

  void Callbacks::removeCallback(triton::callbacks::callback_e kind, getConcreteRegisterValueCallback cb)
  {
    if (kind != triton::callbacks::GET_CONCRETE_REGISTER_VALUE)
      throw triton::exceptions::Exception("Callback of kind GET_CONCRETE_REGISTER_VALUE is expected for removal");

    this->removeSingleCallback(this->getConcreteRegisterValueCallbacks, cb);

    if (this->countCallbacks() == 0)
      this->defined = false;
  }


  void Callbacks::removeCallback(triton::callbacks::callback_e kind, ComparableFunctor<void(triton::Context&, const triton::arch::MemoryAccess&, const triton::uint512& value)> cb) {
    switch (kind) {
      case triton::callbacks::SET_CONCRETE_MEMORY_VALUE:
        this->removeSingleCallback(this->setConcreteMemoryValueCallbacks, cb);
        break;

      default:
        throw triton::exceptions::Exception("Incorrect callback kind for removal");
    }

    if (this->countCallbacks() == 0) {
      this->defined = false;
    }
  }


  void Callbacks::removeCallback(triton::callbacks::callback_e kind, ComparableFunctor<void(triton::Context&, const triton::arch::Register&, const triton::uint512& value)> cb) {
    switch (kind) {
      case triton::callbacks::SET_CONCRETE_REGISTER_VALUE:
        this->removeSingleCallback(this->setConcreteRegisterValueCallbacks, cb);
        break;

      default:
        throw triton::exceptions::Exception("Incorrect callback kind for removal");
    }

    if (this->countCallbacks() == 0) {
      this->defined = false;
    }
  }


  void Callbacks::removeCallback(triton::callbacks::callback_e kind, ComparableFunctor<triton::ast::SharedAbstractNode(triton::Context&, const triton::ast::SharedAbstractNode&)> cb) {
    switch (kind) {
      case triton::callbacks::SYMBOLIC_SIMPLIFICATION:
        this->removeSingleCallback(this->symbolicSimplificationCallbacks, cb);
        break;

      default:
        throw triton::exceptions::Exception("Incorrect callback kind for removal");
    }

    if (this->countCallbacks() == 0) {
      this->defined = false;
    }
  }


  triton::ast::SharedAbstractNode Callbacks::processCallbacks(triton::callbacks::callback_e kind, triton::ast::SharedAbstractNode node) 
  {
    switch (kind) 
    {
      case triton::callbacks::SYMBOLIC_SIMPLIFICATION: 
      {
        for (auto& function: this->symbolicSimplificationCallbacks) 
        {
          // Re-inject node in next callback
          node = function(this->ctx, node);
          if (node == nullptr)
            throw triton::exceptions::Callbacks("Callbacks::processCallbacks(SYMBOLIC_SIMPLIFICATION): You cannot return a nullptr node.");
        }
        return node;
      }

      default:
        throw triton::exceptions::Callbacks("Callbacks::processCallbacks(): Invalid kind of callback for this C++ polymorphism.");
    }
  }

  void Callbacks::processCallbacks(triton::callbacks::callback_e kind, const triton::arch::MemoryAccess& mem) 
  {
    switch (kind) 
    {
      case triton::callbacks::GET_CONCRETE_MEMORY_VALUE: 
      {
        // Check if we are already in the callback to avoid infinite recursion
        if (this->mload)
          break;

        for (auto& function: this->getConcreteMemoryValueCallbacks) 
        {
          this->mload = true;
          function(this->ctx, mem);
          if (mem.getLeaAst() != nullptr) 
            this->ctx.getSymbolicEngine()->initLeaAst(const_cast<triton::arch::MemoryAccess&>(mem));

          this->mload = false;
        }

        break;
      }

      default:
        throw triton::exceptions::Callbacks("Callbacks::processCallbacks(): Invalid kind of callback for this C++ polymorphism.");
    }
  }


  void Callbacks::processCallbacks(triton::callbacks::callback_e kind, const triton::arch::Register& reg) {
    switch (kind) {
      case triton::callbacks::GET_CONCRETE_REGISTER_VALUE: {
        /* Check if we are already in the callback to avoid infinite recursion */
        if (this->mget) {
          break;
        }

        for (auto& function: this->getConcreteRegisterValueCallbacks) {
          this->mget = true;
          function(this->ctx, reg);
          this->mget = false;
        }

        break;
      }

      default:
        throw triton::exceptions::Callbacks("Callbacks::processCallbacks(): Invalid kind of callback for this C++ polymorphism.");
    };
  }

  void Callbacks::processCallbacks(triton::callbacks::callback_e kind, const triton::arch::MemoryAccess& mem, const triton::uint512& value) 
  {
    switch (kind) {
      case triton::callbacks::SET_CONCRETE_MEMORY_VALUE: {
        /* Check if we are already in the callback to avoid infinite recursion */
        if (this->mstore) {
          break;
        }

        for (auto& function: this->setConcreteMemoryValueCallbacks) {
          this->mstore = true;
          function(this->ctx, mem, value);
          this->mstore = false;
        }

        break;
      }

      default:
        throw triton::exceptions::Callbacks("Callbacks::processCallbacks(): Invalid kind of callback for this C++ polymorphism.");
    };
  }


  void Callbacks::processCallbacks(
    triton::callbacks::callback_e kind, 
    const triton::arch::Register& reg, 
    const triton::uint512& value) 
  {
    if (kind != triton::callbacks::SET_CONCRETE_REGISTER_VALUE)
      throw triton::exceptions::Callbacks("Callbacks::processCallbacks(): SET_CONCRETE_REGISTER_VALUE kind expected!");

    // Check if we are already in the callback to avoid infinite recursion
    if (this->mput)
      return;

    for (auto& function: this->setConcreteRegisterValueCallbacks) 
    {
      this->mput = true;
      function(this->ctx, reg, value);
      this->mput = false;
    }
  }

  triton::usize Callbacks::countCallbacks(void) const 
  {
    triton::usize count = 0;

    count += this->getConcreteMemoryValueCallbacks.size();
    count += this->getConcreteRegisterValueCallbacks.size();
    count += this->setConcreteMemoryValueCallbacks.size();
    count += this->setConcreteRegisterValueCallbacks.size();
    count += this->symbolicSimplificationCallbacks.size();

    return count;
  }

  bool Callbacks::isDefined(triton::callbacks::callback_e kind) const 
  {
    switch (kind) 
    {
      case GET_CONCRETE_MEMORY_VALUE:   
        return !this->getConcreteMemoryValueCallbacks.empty();
      case GET_CONCRETE_REGISTER_VALUE: 
        return !this->getConcreteRegisterValueCallbacks.empty();
      case SET_CONCRETE_MEMORY_VALUE:   
        return !this->setConcreteMemoryValueCallbacks.empty();
      case SET_CONCRETE_REGISTER_VALUE: 
        return !this->setConcreteRegisterValueCallbacks.empty();
      case SYMBOLIC_SIMPLIFICATION:     
        return !this->symbolicSimplificationCallbacks.empty();
      default:
        return false;
    }
  }
}
