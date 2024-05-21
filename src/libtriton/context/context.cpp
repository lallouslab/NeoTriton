//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#include <triton/aarch64Cpu.hpp>
#include <triton/arm32Cpu.hpp>
#include <triton/config.hpp>
#include <triton/context.hpp>
#include <triton/exceptions.hpp>
#include <triton/x8664Cpu.hpp>
#include <triton/x86Cpu.hpp>

#include <list>
#include <map>
#include <memory>
#include <new>

using namespace triton;

Context::Context() : callbacks(*this), arch(&this->callbacks)
{
  this->modes = std::make_shared<modes::Modes>();
  this->astCtxt = std::make_shared<ast::AstContext>(this->modes);
}

Context::Context(arch::architecture_e arch) : Context()
{
  this->setArchitecture(arch);
}

Context::~Context() {
  this->removeEngines();
}


inline void Context::checkArchitecture(void) const {
  if (!this->isArchitectureValid())
    throw exceptions::Context("Context::checkArchitecture(): You must define an architecture.");
}


inline void Context::checkIrBuilder(void) const {
  if (!this->irBuilder)
    throw exceptions::Context("Context::checkIrBuilder(): IR builder is undefined, you should define an architecture first.");
}


inline void Context::checkSymbolic(void) const {
  if (!this->symbolic)
    throw exceptions::Context("Context::checkSymbolic(): Symbolic engine is undefined, you should define an architecture first.");
}


inline void Context::checkSolver(void) const {
  if (!this->solver)
    throw exceptions::Context("Context::checkSolver(): Solver engine is undefined, you should define an architecture first.");
}


inline void Context::checkTaint(void) const {
  if (!this->taint)
    throw exceptions::Context("Context::checkTaint(): Taint engine is undefined, you should define an architecture first.");
}


inline void Context::checkLifting(void) const {
  if (!this->lifting)
    throw exceptions::Context("Context::checkLifting(): Lifting engine is undefined, you should define an architecture first.");
}



/* Architecture Context ============================================================================== */

bool Context::isArchitectureValid(void) const {
  return this->arch.isValid();
}


arch::architecture_e Context::getArchitecture(void) const {
  return this->arch.getArchitecture();
}


arch::endianness_e Context::getEndianness(void) const {
  return this->arch.getEndianness();
}


arch::CpuInterface* Context::getCpuInstance(void) {
  if (!this->isArchitectureValid())
    throw exceptions::Context("Context::checkArchitecture(): You must define an architecture.");
  return this->arch.getCpuInstance();
}


void Context::setArchitecture(arch::architecture_e arch) {
  /* Setup and init the targeted architecture */
  this->arch.setArchitecture(arch);

  /* remove and re-init previous engines (when setArchitecture() has been called twice) */
  this->removeEngines();
  this->initEngines();
}


void Context::clearArchitecture(void) {
  this->checkArchitecture();
  this->arch.clearArchitecture();
}


bool Context::isFlag(arch::register_e regId) const {
  return this->arch.isFlag(regId);
}


bool Context::isFlag(const arch::Register& reg) const {
  return this->arch.isFlag(reg);
}


bool Context::isRegister(arch::register_e regId) const {
  return this->arch.isRegister(regId);
}


bool Context::isRegister(const arch::Register& reg) const {
  return this->arch.isRegister(reg);
}


const arch::Register& Context::getRegister(arch::register_e id) const {
  return this->arch.getRegister(id);
}


const arch::Register& Context::getRegister(const std::string& name) const {
  return this->arch.getRegister(name);
}


const arch::Register& Context::getParentRegister(const arch::Register& reg) const {
  return this->arch.getParentRegister(reg);
}


const arch::Register& Context::getParentRegister(arch::register_e id) const {
  return this->arch.getParentRegister(id);
}


bool Context::isRegisterValid(arch::register_e regId) const {
  return this->arch.isRegisterValid(regId);
}


bool Context::isRegisterValid(const arch::Register& reg) const {
  return this->arch.isRegisterValid(reg);
}


bool Context::isThumb(void) const {
  return this->arch.isThumb();
}


void Context::setThumb(bool state) {
  this->arch.setThumb(state);
}


uint32 Context::getGprBitSize(void) const {
  return this->arch.gprBitSize();
}


uint32 Context::getGprSize(void) const {
  return this->arch.gprSize();
}


uint32 Context::getNumberOfRegisters(void) const {
  return this->arch.numberOfRegisters();
}


const arch::Instruction Context::getNopInstruction(void) const {
  return this->arch.getNopInstruction();
}


const std::unordered_map<arch::register_e, const arch::Register>& Context::getAllRegisters(void) const {
  this->checkArchitecture();
  return this->arch.getAllRegisters();
}

const std::unordered_map<uint64, uint8, IdentityHash<uint64>>& Context::getConcreteMemory(void) const {
  this->checkArchitecture();
  return this->arch.getConcreteMemory();
}


std::set<const arch::Register*> Context::getParentRegisters(void) const {
  this->checkArchitecture();
  return this->arch.getParentRegisters();
}


uint8 Context::getConcreteMemoryValue(uint64 addr, bool execCallbacks) const {
  this->checkArchitecture();
  return this->arch.getConcreteMemoryValue(addr, execCallbacks);
}


uint512 Context::getConcreteMemoryValue(const arch::MemoryAccess& mem, bool execCallbacks) const {
  this->checkArchitecture();
  return this->arch.getConcreteMemoryValue(mem, execCallbacks);
}


bytes Context::getConcreteMemoryAreaValue(uint64 baseAddr, usize size, bool execCallbacks) const {
  this->checkArchitecture();
  return this->arch.getConcreteMemoryAreaValue(baseAddr, size, execCallbacks);
}


uint512 Context::getConcreteRegisterValue(const arch::Register& reg, bool execCallbacks) const {
  this->checkArchitecture();
  return this->arch.getConcreteRegisterValue(reg, execCallbacks);
}



void Context::setConcreteMemoryValue(uint64 addr, uint8 value, bool execCallbacks) {
  this->checkArchitecture();
  this->arch.setConcreteMemoryValue(addr, value, execCallbacks);
  /*
    * In order to synchronize the concrete state with the symbolic
    * one, the symbolic expression is concretized.
    */
  this->concretizeMemory(addr);
}


void Context::setConcreteMemoryValue(const arch::MemoryAccess& mem, const uint512& value, bool execCallbacks) {
  this->checkArchitecture();
  this->arch.setConcreteMemoryValue(mem, value, execCallbacks);
  /*
    * In order to synchronize the concrete state with the symbolic
    * one, the symbolic expression is concretized.
    */
  this->concretizeMemory(mem);
}


void Context::setConcreteMemoryAreaValue(uint64 baseAddr, const bytes& values, bool execCallbacks) {
  this->checkArchitecture();
  this->arch.setConcreteMemoryAreaValue(baseAddr, values, execCallbacks);
  /*
    * In order to synchronize the concrete state with the symbolic
    * one, the symbolic expression is concretized.
    */
  for (usize index = 0; index < values.size(); index++) {
    this->concretizeMemory(baseAddr + index);
  }
}


void Context::setConcreteMemoryAreaValue(uint64 baseAddr, const void* area, usize size, bool execCallbacks) {
  this->checkArchitecture();
  this->arch.setConcreteMemoryAreaValue(baseAddr, area, size, execCallbacks);
  /*
    * In order to synchronize the concrete state with the symbolic
    * one, the symbolic expression is concretized.
    */
  for (usize index = 0; index < size; index++) {
    this->concretizeMemory(baseAddr + index);
  }
}


void Context::setConcreteRegisterValue(const arch::Register& reg, const uint512& value, bool execCallbacks) {
  this->checkArchitecture();
  this->arch.setConcreteRegisterValue(reg, value, execCallbacks);
  /*
    * In order to synchronize the concrete state with the symbolic
    * one, the symbolic expression is concretized.
    */
  this->concretizeRegister(reg);
}


void Context::setConcreteState(arch::Architecture& other) {
  if (this->getArchitecture() != other.getArchitecture()) {
    throw exceptions::Engines("Context::setConcreteState(): Not the same architecture.");
  }

  switch (this->getArchitecture())
  {
  case arch::ARCH_X86_64:
    *static_cast<arch::x86::x8664Cpu*>(this->getCpuInstance()) = *static_cast<arch::x86::x8664Cpu*>(other.getCpuInstance());
    break;
  case arch::ARCH_X86:
    *static_cast<arch::x86::x86Cpu*>(this->getCpuInstance()) = *static_cast<arch::x86::x86Cpu*>(other.getCpuInstance());
    break;
  case arch::ARCH_ARM32:
    *static_cast<arch::arm::arm32::Arm32Cpu*>(this->getCpuInstance()) = *static_cast<arch::arm::arm32::Arm32Cpu*>(other.getCpuInstance());
    break;
  case arch::ARCH_AARCH64:
    *static_cast<arch::arm::aarch64::AArch64Cpu*>(this->getCpuInstance()) = *static_cast<arch::arm::aarch64::AArch64Cpu*>(other.getCpuInstance());
    break;
  default:
    throw exceptions::Engines("Context::setConcreteState(): Invalid architecture.");
  }

  this->concretizeAllMemory();
  this->concretizeAllRegister();
}


bool Context::isConcreteMemoryValueDefined(const arch::MemoryAccess& mem) const {
  this->checkArchitecture();
  return this->arch.isConcreteMemoryValueDefined(mem);
}


bool Context::isConcreteMemoryValueDefined(uint64 baseAddr, usize size) const {
  this->checkArchitecture();
  return this->arch.isConcreteMemoryValueDefined(baseAddr, size);
}


void Context::clearConcreteMemoryValue(const arch::MemoryAccess& mem) {
  this->checkArchitecture();
  this->arch.clearConcreteMemoryValue(mem);
}


void Context::clearConcreteMemoryValue(uint64 baseAddr, usize size) {
  this->checkArchitecture();
  this->arch.clearConcreteMemoryValue(baseAddr, size);
}


void Context::disassembly(arch::Instruction& inst) const {
  this->checkArchitecture();
  this->arch.disassembly(inst);
}


void Context::disassembly(arch::BasicBlock& block, uint64 addr) const {
  this->checkArchitecture();
  this->arch.disassembly(block, addr);
}


std::vector<arch::Instruction> Context::disassembly(uint64 addr, usize count) const {
  this->checkArchitecture();
  return this->arch.disassembly(addr, count);
}


arch::BasicBlock Context::disassembly(uint64 addr, bool(*filterCallback)(std::vector<arch::Instruction>&)) const {
  this->checkArchitecture();
  return this->arch.disassembly(addr, filterCallback);
}


arch::BasicBlock Context::disassembly(uint64 addr) const {
  this->checkArchitecture();
  return this->arch.disassembly(addr);
}



/* Processing Context ================================================================================ */

void Context::initEngines(void) {
  this->checkArchitecture();

  this->symbolic = new(std::nothrow) engines::symbolic::SymbolicEngine(&this->arch, this->modes, this->astCtxt, &this->callbacks);
  if (this->symbolic == nullptr)
    throw exceptions::Context("Context::initEngines(): Not enough memory.");

  this->solver = new(std::nothrow) engines::solver::SolverEngine();
  if (this->solver == nullptr)
    throw exceptions::Context("Context::initEngines(): Not enough memory.");

  this->taint = new(std::nothrow) engines::taint::TaintEngine(this->modes, this->symbolic, *this->getCpuInstance());
  if (this->taint == nullptr)
    throw exceptions::Context("Context::initEngines(): Not enough memory.");

  this->lifting = new(std::nothrow) engines::lifters::LiftingEngine(this->astCtxt, this->symbolic);
  if (this->lifting == nullptr)
    throw exceptions::Context("Context::initEngines(): Not enough memory.");

  this->irBuilder = new(std::nothrow) arch::IrBuilder(&this->arch, this->modes, this->astCtxt, this->symbolic, this->taint);
  if (this->irBuilder == nullptr)
    throw exceptions::Context("Context::initEngines(): Not enough memory.");

  /* Setup registers shortcut */
  this->registers.init(this->arch.getArchitecture());
}


void Context::removeEngines(void) {
  if (this->isArchitectureValid()) {
    delete this->irBuilder;
    delete this->lifting;
    delete this->solver;
    delete this->symbolic;
    delete this->taint;

    this->astCtxt = nullptr;
    this->irBuilder = nullptr;
    this->lifting = nullptr;
    this->solver = nullptr;
    this->symbolic = nullptr;
    this->taint = nullptr;
  }

  // Clean up the ast context
  this->astCtxt = std::make_shared<ast::AstContext>(this->modes);

  // Clean up the registers shortcut
  this->registers.clear();
}


void Context::reset(void) {
  if (this->isArchitectureValid()) {
    this->removeEngines();
    this->initEngines();
    this->clearArchitecture();
    this->clearCallbacks();
    this->clearModes();
  }
}


arch::exception_e Context::processing(arch::Instruction& inst) {
  this->checkArchitecture();
  this->arch.disassembly(inst);
  return this->irBuilder->buildSemantics(inst);
}


arch::exception_e Context::processing(arch::BasicBlock& block, uint64 addr) {
  this->checkArchitecture();
  this->arch.disassembly(block, addr);
  return this->irBuilder->buildSemantics(block);
}



/* IR builder Context ================================================================================= */

arch::exception_e Context::buildSemantics(arch::Instruction& inst) {
  this->checkIrBuilder();
  return this->irBuilder->buildSemantics(inst);
}


arch::exception_e Context::buildSemantics(arch::BasicBlock& block) {
  this->checkIrBuilder();
  return this->irBuilder->buildSemantics(block);
}


ast::SharedAstContext Context::getAstContext(void) {
  return this->astCtxt;
}



/* AST representation Context ========================================================================= */

ast::representations::mode_e Context::getAstRepresentationMode(void) const {
  return this->astCtxt->getRepresentationMode();
}


void Context::setAstRepresentationMode(ast::representations::mode_e mode) {
  this->astCtxt->setRepresentationMode(mode);
}



/* Callbacks Context ================================================================================= */

template TRITON_EXPORT void Context::addCallback(callbacks::callback_e kind, ComparableFunctor<void(Context&, const arch::MemoryAccess&)> cb);
template TRITON_EXPORT void Context::addCallback(callbacks::callback_e kind, ComparableFunctor<void(Context&, const arch::Register&)> cb);
template TRITON_EXPORT void Context::addCallback(callbacks::callback_e kind, ComparableFunctor<void(Context&, const arch::MemoryAccess&, const uint512& value)> cb);
template TRITON_EXPORT void Context::addCallback(callbacks::callback_e kind, ComparableFunctor<void(Context&, const arch::Register&, const uint512& value)> cb);
template TRITON_EXPORT void Context::addCallback(callbacks::callback_e kind, ComparableFunctor<ast::SharedAbstractNode(Context&, const ast::SharedAbstractNode&)> cb);

template TRITON_EXPORT void Context::removeCallback(callbacks::callback_e kind, ComparableFunctor<void(Context&, const arch::MemoryAccess&)> cb);
template TRITON_EXPORT void Context::removeCallback(callbacks::callback_e kind, ComparableFunctor<void(Context&, const arch::Register&)> cb);
template TRITON_EXPORT void Context::removeCallback(callbacks::callback_e kind, ComparableFunctor<void(Context&, const arch::MemoryAccess&, const uint512& value)> cb);
template TRITON_EXPORT void Context::removeCallback(callbacks::callback_e kind, ComparableFunctor<void(Context&, const arch::Register&, const uint512& value)> cb);
template TRITON_EXPORT void Context::removeCallback(callbacks::callback_e kind, ComparableFunctor<ast::SharedAbstractNode(Context&, const ast::SharedAbstractNode&)> cb);


void Context::clearCallbacks(void) {
  this->callbacks.clearCallbacks();
}


ast::SharedAbstractNode Context::processCallbacks(callbacks::callback_e kind, ast::SharedAbstractNode node) {
  if (this->callbacks.isDefined()) {
    return this->callbacks.processCallbacks(kind, node);
  }
  return node;
}


void Context::processCallbacks(callbacks::callback_e kind, const arch::MemoryAccess& mem) {
  if (this->callbacks.isDefined()) {
    this->callbacks.processCallbacks(kind, mem);
  }
}


void Context::processCallbacks(callbacks::callback_e kind, const arch::Register& reg) {
  if (this->callbacks.isDefined()) {
    this->callbacks.processCallbacks(kind, reg);
  }
}



/* Modes Context======================================================================================= */

void Context::setMode(modes::mode_e mode, bool flag) {
  this->modes->setMode(mode, flag);
}


bool Context::isModeEnabled(modes::mode_e mode) const {
  return this->modes->isModeEnabled(mode);
}


void Context::clearModes(void) {
  this->modes->clearModes();
}



/* Symbolic engine Context ============================================================================ */

engines::symbolic::SymbolicEngine* Context::getSymbolicEngine(void) {
  this->checkSymbolic();
  return this->symbolic;
}


engines::symbolic::SharedSymbolicVariable Context::symbolizeExpression(usize exprId, uint32 symVarSize, const std::string& symVarAlias) {
  this->checkSymbolic();
  return this->symbolic->symbolizeExpression(exprId, symVarSize, symVarAlias);
}


engines::symbolic::SharedSymbolicVariable Context::symbolizeMemory(const arch::MemoryAccess& mem, const std::string& symVarAlias) {
  this->checkSymbolic();
  return this->symbolic->symbolizeMemory(mem, symVarAlias);
}


void Context::symbolizeMemory(uint64 addr, usize size) {
  this->checkSymbolic();
  this->symbolic->symbolizeMemory(addr, size);
}


engines::symbolic::SharedSymbolicVariable Context::symbolizeRegister(const arch::Register& reg, const std::string& symVarAlias) {
  this->checkSymbolic();
  return this->symbolic->symbolizeRegister(reg, symVarAlias);
}


ast::SharedAbstractNode Context::getOperandAst(const arch::OperandWrapper& op) {
  this->checkSymbolic();
  return this->symbolic->getOperandAst(op);
}


ast::SharedAbstractNode Context::getOperandAst(arch::Instruction& inst, const arch::OperandWrapper& op) {
  this->checkSymbolic();
  return this->symbolic->getOperandAst(inst, op);
}


ast::SharedAbstractNode Context::getImmediateAst(const arch::Immediate& imm) {
  this->checkSymbolic();
  return this->symbolic->getImmediateAst(imm);
}


ast::SharedAbstractNode Context::getImmediateAst(arch::Instruction& inst, const arch::Immediate& imm) {
  this->checkSymbolic();
  return this->symbolic->getImmediateAst(inst, imm);
}


ast::SharedAbstractNode Context::getMemoryAst(const arch::MemoryAccess& mem) {
  this->checkSymbolic();
  return this->symbolic->getMemoryAst(mem);
}


ast::SharedAbstractNode Context::getMemoryAst(arch::Instruction& inst, const arch::MemoryAccess& mem) {
  this->checkSymbolic();
  return this->symbolic->getMemoryAst(inst, mem);
}


ast::SharedAbstractNode Context::getRegisterAst(const arch::Register& reg) {
  this->checkSymbolic();
  return this->symbolic->getRegisterAst(reg);
}


ast::SharedAbstractNode Context::getRegisterAst(arch::Instruction& inst, const arch::Register& reg) {
  this->checkSymbolic();
  return this->symbolic->getRegisterAst(inst, reg);
}


engines::symbolic::SharedSymbolicExpression Context::newSymbolicExpression(const ast::SharedAbstractNode& node, const std::string& comment) {
  this->checkSymbolic();
  return this->symbolic->newSymbolicExpression(node, engines::symbolic::VOLATILE_EXPRESSION, comment);
}


engines::symbolic::SharedSymbolicVariable Context::newSymbolicVariable(uint32 varSize, const std::string& alias) {
  this->checkSymbolic();
  return this->symbolic->newSymbolicVariable(engines::symbolic::UNDEFINED_VARIABLE, 0, varSize, alias);
}


void Context::removeSymbolicExpression(const engines::symbolic::SharedSymbolicExpression& expr) {
  this->checkSymbolic();
  return this->symbolic->removeSymbolicExpression(expr);
}


const engines::symbolic::SharedSymbolicExpression& Context::createSymbolicExpression(arch::Instruction& inst, const ast::SharedAbstractNode& node, const arch::OperandWrapper& dst, const std::string& comment) {
  this->checkSymbolic();
  return this->symbolic->createSymbolicExpression(inst, node, dst, comment);
}


const engines::symbolic::SharedSymbolicExpression& Context::createSymbolicMemoryExpression(arch::Instruction& inst, const ast::SharedAbstractNode& node, const arch::MemoryAccess& mem, const std::string& comment) {
  this->checkSymbolic();
  return this->symbolic->createSymbolicMemoryExpression(inst, node, mem, comment);
}


const engines::symbolic::SharedSymbolicExpression& Context::createSymbolicRegisterExpression(arch::Instruction& inst, const ast::SharedAbstractNode& node, const arch::Register& reg, const std::string& comment) {
  this->checkSymbolic();
  return this->symbolic->createSymbolicRegisterExpression(inst, node, reg, comment);
}


const engines::symbolic::SharedSymbolicExpression& Context::createSymbolicVolatileExpression(arch::Instruction& inst, const ast::SharedAbstractNode& node, const std::string& comment) {
  this->checkSymbolic();
  return this->symbolic->createSymbolicVolatileExpression(inst, node, comment);
}


void Context::assignSymbolicExpressionToMemory(const engines::symbolic::SharedSymbolicExpression& se, const arch::MemoryAccess& mem) {
  this->checkSymbolic();
  this->symbolic->assignSymbolicExpressionToMemory(se, mem);
}


void Context::assignSymbolicExpressionToRegister(const engines::symbolic::SharedSymbolicExpression& se, const arch::Register& reg) {
  this->checkSymbolic();
  this->symbolic->assignSymbolicExpressionToRegister(se, reg);
}


engines::symbolic::SharedSymbolicExpression Context::getSymbolicMemory(uint64 addr) const {
  this->checkSymbolic();
  return this->symbolic->getSymbolicMemory(addr);
}


std::unordered_map<arch::register_e, engines::symbolic::SharedSymbolicExpression> Context::getSymbolicRegisters(void) const {
  this->checkSymbolic();
  return this->symbolic->getSymbolicRegisters();
}


std::unordered_map<uint64, engines::symbolic::SharedSymbolicExpression> Context::getSymbolicMemory(void) const {
  this->checkSymbolic();
  return this->symbolic->getSymbolicMemory();
}


const engines::symbolic::SharedSymbolicExpression& Context::getSymbolicRegister(const arch::Register& reg) const {
  this->checkSymbolic();
  return this->symbolic->getSymbolicRegister(reg);
}


uint8 Context::getSymbolicMemoryValue(uint64 address) {
  this->checkSymbolic();
  return this->symbolic->getSymbolicMemoryValue(address);
}


uint512 Context::getSymbolicMemoryValue(const arch::MemoryAccess& mem) {
  this->checkSymbolic();
  return this->symbolic->getSymbolicMemoryValue(mem);
}


bytes Context::getSymbolicMemoryAreaValue(uint64 baseAddr, usize size) {
  this->checkSymbolic();
  return this->symbolic->getSymbolicMemoryAreaValue(baseAddr, size);
}


uint512 Context::getSymbolicRegisterValue(const arch::Register& reg) {
  this->checkSymbolic();
  return this->symbolic->getSymbolicRegisterValue(reg);
}


ast::SharedAbstractNode Context::simplify(const ast::SharedAbstractNode& node, bool usingSolver, bool usingLLVM) const {
  if (usingSolver) {
    return this->simplifyAstViaSolver(node);
  }
  else if (usingLLVM) {
    return this->simplifyAstViaLLVM(node);
  }
  else {
    this->checkSymbolic();
    return this->symbolic->simplify(node);
  }
}


arch::BasicBlock Context::simplify(const arch::BasicBlock& block, bool padding) const {
  this->checkSymbolic();
  return this->symbolic->simplify(block, padding);
}


engines::symbolic::SharedSymbolicExpression Context::getSymbolicExpression(usize symExprId) const {
  this->checkSymbolic();
  return this->symbolic->getSymbolicExpression(symExprId);
}


uint512 Context::getConcreteVariableValue(const engines::symbolic::SharedSymbolicVariable& symVar) const {
  this->checkSymbolic();
  return this->symbolic->getConcreteVariableValue(symVar);
}


void Context::setConcreteVariableValue(const engines::symbolic::SharedSymbolicVariable& symVar, const uint512& value) {
  this->checkSymbolic();
  this->symbolic->setConcreteVariableValue(symVar, value);
}


engines::symbolic::SharedSymbolicVariable Context::getSymbolicVariable(usize symVarId) const {
  this->checkSymbolic();
  return this->symbolic->getSymbolicVariable(symVarId);
}


engines::symbolic::SharedSymbolicVariable Context::getSymbolicVariable(const std::string& symVarName) const {
  this->checkSymbolic();
  return this->symbolic->getSymbolicVariable(symVarName);
}


const std::vector<engines::symbolic::PathConstraint>& Context::getPathConstraints(void) const {
  this->checkSymbolic();
  return this->symbolic->getPathConstraints();
}


std::vector<engines::symbolic::PathConstraint> Context::getPathConstraints(usize start, usize end) const {
  this->checkSymbolic();
  return this->symbolic->getPathConstraints(start, end);
}


std::vector<engines::symbolic::PathConstraint> Context::getPathConstraintsOfThread(uint32 threadId) const {
  this->checkSymbolic();
  return this->symbolic->getPathConstraintsOfThread(threadId);
}


usize Context::getSizeOfPathConstraints(void) const {
  this->checkSymbolic();
  return this->symbolic->getSizeOfPathConstraints();
}


ast::SharedAbstractNode Context::getPathPredicate(void) {
  this->checkSymbolic();
  return this->symbolic->getPathPredicate();
}


std::vector<ast::SharedAbstractNode> Context::getPredicatesToReachAddress(uint64 addr) {
  this->checkSymbolic();
  return this->symbolic->getPredicatesToReachAddress(addr);
}


void Context::pushPathConstraint(const ast::SharedAbstractNode& node, const std::string& comment) {
  this->checkSymbolic();
  this->symbolic->pushPathConstraint(node, comment);
}


void Context::pushPathConstraint(const engines::symbolic::PathConstraint& pco) {
  this->checkSymbolic();
  this->symbolic->pushPathConstraint(pco);
}


void Context::popPathConstraint(void) {
  this->checkSymbolic();
  this->symbolic->popPathConstraint();
}


void Context::clearPathConstraints(void) {
  this->checkSymbolic();
  this->symbolic->clearPathConstraints();
}


bool Context::isSymbolicExpressionExists(usize symExprId) const {
  this->checkSymbolic();
  return this->symbolic->isSymbolicExpressionExists(symExprId);
}


bool Context::isMemorySymbolized(const arch::MemoryAccess& mem) const {
  this->checkSymbolic();
  return this->symbolic->isMemorySymbolized(mem);
}


bool Context::isMemorySymbolized(uint64 addr, uint32 size) const {
  this->checkSymbolic();
  return this->symbolic->isMemorySymbolized(addr, size);
}


bool Context::isRegisterSymbolized(const arch::Register& reg) const {
  this->checkSymbolic();
  return this->symbolic->isRegisterSymbolized(reg);
}


void Context::concretizeAllMemory(void) {
  this->checkSymbolic();
  this->symbolic->concretizeAllMemory();
}


void Context::concretizeAllRegister(void) {
  this->checkSymbolic();
  this->symbolic->concretizeAllRegister();
}


void Context::concretizeMemory(const arch::MemoryAccess& mem) {
  this->checkSymbolic();
  this->symbolic->concretizeMemory(mem);
}


void Context::concretizeMemory(uint64 addr) {
  this->checkSymbolic();
  this->symbolic->concretizeMemory(addr);
}


void Context::concretizeRegister(const arch::Register& reg) {
  this->checkSymbolic();
  this->symbolic->concretizeRegister(reg);
}


std::unordered_map<usize, engines::symbolic::SharedSymbolicExpression> Context::sliceExpressions(const engines::symbolic::SharedSymbolicExpression& expr) {
  this->checkSymbolic();
  return this->symbolic->sliceExpressions(expr);
}


std::vector<engines::symbolic::SharedSymbolicExpression> Context::getTaintedSymbolicExpressions(void) const {
  this->checkSymbolic();
  return this->symbolic->getTaintedSymbolicExpressions();
}


std::unordered_map<usize, engines::symbolic::SharedSymbolicExpression> Context::getSymbolicExpressions(void) const {
  this->checkSymbolic();
  return this->symbolic->getSymbolicExpressions();
}


std::map<usize, engines::symbolic::SharedSymbolicVariable> Context::getSymbolicVariables(void) const {
  this->checkSymbolic();
  return this->symbolic->getSymbolicVariables();
}



/* Solver engine Context ============================================================================= */

engines::solver::solver_e Context::getSolver(void) const {
  this->checkSolver();
  return this->solver->getSolver();
}


const engines::solver::SolverInterface* Context::getSolverInstance(void) const {
  this->checkSolver();
  return this->solver->getSolverInstance();
}


void Context::setSolver(engines::solver::solver_e kind) {
  this->checkSolver();
  this->solver->setSolver(kind);
}


void Context::setCustomSolver(engines::solver::SolverInterface* customSolver) {
  this->checkSolver();
  this->solver->setCustomSolver(customSolver);
}


bool Context::isSolverValid(void) const {
  this->checkSolver();
  return this->solver->isValid();
}


std::unordered_map<usize, engines::solver::SolverModel> Context::getModel(const ast::SharedAbstractNode& node, engines::solver::status_e* status, uint32 timeout, uint32* solvingTime) const {
  this->checkSolver();
  return this->solver->getModel(node, status, timeout, solvingTime);
}


std::vector<std::unordered_map<usize, engines::solver::SolverModel>> Context::getModels(const ast::SharedAbstractNode& node, uint32 limit, engines::solver::status_e* status, uint32 timeout, uint32* solvingTime) const {
  this->checkSolver();
  return this->solver->getModels(node, limit, status, timeout, solvingTime);
}


bool Context::isSat(const ast::SharedAbstractNode& node, engines::solver::status_e* status, uint32 timeout, uint32* solvingTime) const {
  this->checkSolver();
  return this->solver->isSat(node, status, timeout, solvingTime);
}


uint512 Context::evaluateAstViaSolver(const ast::SharedAbstractNode& node) const {
  this->checkSolver();
#ifdef TRITON_Z3_INTERFACE
  if (this->getSolver() == engines::solver::SOLVER_Z3) {
    return reinterpret_cast<const engines::solver::Z3Solver*>(this->getSolverInstance())->evaluate(node);
  }
#endif
#ifdef TRITON_BITWUZLA_INTERFACE
  if (this->getSolver() == engines::solver::SOLVER_BITWUZLA) {
    return reinterpret_cast<const engines::solver::BitwuzlaSolver*>(this->getSolverInstance())->evaluate(node);
  }
#endif
  throw exceptions::Context("Context::evaluateAstViaZ3(): Solver instance must be a SOLVER_Z3 or SOLVER_BITWUZLA.");
}


ast::SharedAbstractNode Context::simplifyAstViaSolver(const ast::SharedAbstractNode& node) const {
  this->checkSolver();
#ifdef TRITON_Z3_INTERFACE
  if (this->getSolver() == engines::solver::SOLVER_Z3) {
    return reinterpret_cast<const engines::solver::Z3Solver*>(this->getSolverInstance())->simplify(node);
  }
#endif
  throw exceptions::Context("Context::simplifyAstViaSolver(): Solver instance must be a SOLVER_Z3.");
}


void Context::setSolverTimeout(uint32 ms) {
  this->checkSolver();
  this->solver->setTimeout(ms);
}


void Context::setSolverMemoryLimit(uint32 limit) {
  this->checkSolver();
  this->solver->setMemoryLimit(limit);
}



/* Taint engine Context ============================================================================== */

engines::taint::TaintEngine* Context::getTaintEngine(void) {
  this->checkTaint();
  return this->taint;
}


const std::unordered_set<uint64>& Context::getTaintedMemory(void) const {
  this->checkTaint();
  return this->taint->getTaintedMemory();
}


std::unordered_set<const arch::Register*> Context::getTaintedRegisters(void) const {
  this->checkTaint();
  return this->taint->getTaintedRegisters();
}


bool Context::isTainted(const arch::OperandWrapper& op) const {
  this->checkTaint();
  return this->taint->isTainted(op);
}


bool Context::isMemoryTainted(uint64 addr, uint32 size) const {
  this->checkTaint();
  return this->taint->isMemoryTainted(addr, size);
}


bool Context::isMemoryTainted(const arch::MemoryAccess& mem) const {
  this->checkTaint();
  return this->taint->isMemoryTainted(mem);
}


bool Context::isRegisterTainted(const arch::Register& reg) const {
  this->checkTaint();
  return this->taint->isRegisterTainted(reg);
}


bool Context::setTaint(const arch::OperandWrapper& op, bool flag) {
  this->checkTaint();
  return this->taint->setTaint(op, flag);
}


bool Context::setTaintMemory(const arch::MemoryAccess& mem, bool flag) {
  this->checkTaint();
  this->taint->setTaintMemory(mem, flag);
  return flag;
}


bool Context::setTaintRegister(const arch::Register& reg, bool flag) {
  this->checkTaint();
  this->taint->setTaintRegister(reg, flag);
  return flag;
}


bool Context::taintMemory(uint64 addr) {
  this->checkTaint();
  return this->taint->taintMemory(addr);
}


bool Context::taintMemory(const arch::MemoryAccess& mem) {
  this->checkTaint();
  return this->taint->taintMemory(mem);
}


bool Context::taintRegister(const arch::Register& reg) {
  this->checkTaint();
  return this->taint->taintRegister(reg);
}


bool Context::untaintMemory(uint64 addr) {
  this->checkTaint();
  return this->taint->untaintMemory(addr);
}


bool Context::untaintMemory(const arch::MemoryAccess& mem) {
  this->checkTaint();
  return this->taint->untaintMemory(mem);
}


bool Context::untaintRegister(const arch::Register& reg) {
  this->checkTaint();
  return this->taint->untaintRegister(reg);
}


bool Context::taintUnion(const arch::OperandWrapper& op1, const arch::OperandWrapper& op2) {
  this->checkTaint();
  return this->taint->taintUnion(op1, op2);
}


bool Context::taintUnion(const arch::MemoryAccess& memDst, const arch::Immediate& imm) {
  this->checkTaint();
  return this->taint->taintUnion(memDst, imm);
}


bool Context::taintUnion(const arch::MemoryAccess& memDst, const arch::MemoryAccess& memSrc) {
  this->checkTaint();
  return this->taint->taintUnion(memDst, memSrc);
}


bool Context::taintUnion(const arch::MemoryAccess& memDst, const arch::Register& regSrc) {
  this->checkTaint();
  return this->taint->taintUnion(memDst, regSrc);
}


bool Context::taintUnion(const arch::Register& regDst, const arch::Immediate& imm) {
  this->checkTaint();
  return this->taint->taintUnion(regDst, imm);
}


bool Context::taintUnion(const arch::Register& regDst, const arch::MemoryAccess& memSrc) {
  this->checkTaint();
  return this->taint->taintUnion(regDst, memSrc);
}


bool Context::taintUnion(const arch::Register& regDst, const arch::Register& regSrc) {
  this->checkTaint();
  return this->taint->taintUnion(regDst, regSrc);
}


bool Context::taintAssignment(const arch::OperandWrapper& op1, const arch::OperandWrapper& op2) {
  this->checkTaint();
  return this->taint->taintAssignment(op1, op2);
}


bool Context::taintAssignment(const arch::MemoryAccess& memDst, const arch::Immediate& imm) {
  this->checkTaint();
  return this->taint->taintAssignment(memDst, imm);
}


bool Context::taintAssignment(const arch::MemoryAccess& memDst, const arch::MemoryAccess& memSrc) {
  this->checkTaint();
  return this->taint->taintAssignment(memDst, memSrc);
}


bool Context::taintAssignment(const arch::MemoryAccess& memDst, const arch::Register& regSrc) {
  this->checkTaint();
  return this->taint->taintAssignment(memDst, regSrc);
}


bool Context::taintAssignment(const arch::Register& regDst, const arch::Immediate& imm) {
  this->checkTaint();
  return this->taint->taintAssignment(regDst, imm);
}


bool Context::taintAssignment(const arch::Register& regDst, const arch::MemoryAccess& memSrc) {
  this->checkTaint();
  return this->taint->taintAssignment(regDst, memSrc);
}


bool Context::taintAssignment(const arch::Register& regDst, const arch::Register& regSrc) {
  this->checkTaint();
  return this->taint->taintAssignment(regDst, regSrc);
}



/* Synthesizer engine Context ============================================================================= */

engines::synthesis::SynthesisResult Context::synthesize(
  const ast::SharedAbstractNode& node,
  bool constant,
  bool subexpr,
  bool opaque)
{
  this->checkSymbolic();
  engines::synthesis::Synthesizer synth(this->symbolic);
  return synth.synthesize(node, constant, subexpr, opaque);
}



/* Lifters engine Context ================================================================================= */

std::ostream& Context::liftToLLVM(std::ostream& stream, const ast::SharedAbstractNode& node, const char* fname, bool optimize) {
  this->checkLifting();
#ifdef TRITON_LLVM_INTERFACE
  return this->lifting->liftToLLVM(stream, node, fname, optimize);
#endif
  throw exceptions::Context("Context::liftToLLVM(): Triton not built with LLVM");
}


std::ostream& Context::liftToLLVM(std::ostream& stream, const engines::symbolic::SharedSymbolicExpression& expr, const char* fname, bool optimize) {
  return this->liftToLLVM(stream, expr->getAst(), fname, optimize);
}


std::ostream& Context::liftToPython(std::ostream& stream, const engines::symbolic::SharedSymbolicExpression& expr, bool icomment) {
  this->checkLifting();
  return this->lifting->liftToPython(stream, expr, icomment);
}


std::ostream& Context::liftToSMT(std::ostream& stream, const engines::symbolic::SharedSymbolicExpression& expr, bool assert_, bool icomment) {
  this->checkLifting();
  return this->lifting->liftToSMT(stream, expr, assert_, icomment);
}


std::ostream& Context::liftToDot(std::ostream& stream, const ast::SharedAbstractNode& node) {
  this->checkLifting();
  return this->lifting->liftToDot(stream, node);
}


std::ostream& Context::liftToDot(std::ostream& stream, const engines::symbolic::SharedSymbolicExpression& expr) {
  this->checkLifting();
  return this->lifting->liftToDot(stream, expr);
}


ast::SharedAbstractNode Context::simplifyAstViaLLVM(const ast::SharedAbstractNode& node) const {
  this->checkLifting();
#ifdef TRITON_LLVM_INTERFACE
  return this->lifting->simplifyAstViaLLVM(node);
#endif
  throw exceptions::Context("Context::simplifyAstViaLLVM(): Triton not built with LLVM");
}
