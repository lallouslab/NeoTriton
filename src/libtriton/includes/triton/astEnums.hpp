//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#ifndef TRITON_ASTENUMS_HPP
#define TRITON_ASTENUMS_HPP



//! The Triton namespace
namespace triton {
/*!
 *  \addtogroup triton
 *  @{
 */

  //! The AST namespace
  namespace ast {
  /*!
   *  \ingroup triton
   *  \addtogroup ast
   *  @{
   */

    /*! Enumerates all types of node. Must be prime numbers. */
    enum ast_e {
      INVALID_NODE = 0,          /*!< Invalid node */
      ANY_NODE = INVALID_NODE,   /*!< Any node */
      ASSERT_NODE,               /*!< (assert x) */
      BSWAP_NODE,                /*!< (bswap x) */
      BVADD_NODE,                /*!< (bvadd x y) */
      BVAND_NODE,                /*!< (bvand x y) */
      BVASHR_NODE,               /*!< (bvashr x y) */
      BVLSHR_NODE,               /*!< (bvlshr x y) */
      BVMUL_NODE,                /*!< (bvmul x y) */
      BVNAND_NODE,               /*!< (bvnand x y) */
      BVNEG_NODE,                /*!< (bvneg x) */
      BVNOR_NODE,                /*!< (bvnor x y) */
      BVNOT_NODE,                /*!< (bvnot x) */
      BVOR_NODE,                 /*!< (bvor x y) */
      BVROL_NODE,                /*!< ((_ rotate_left x) y) */
      BVROR_NODE,                /*!< ((_ rotate_right x) y) */
      BVSDIV_NODE,               /*!< (bvsdiv x y) */
      BVSGE_NODE,                /*!< (bvsge x y) */
      BVSGT_NODE,                /*!< (bvsgt x y) */
      BVSHL_NODE,                /*!< (bvshl x y) */
      BVSLE_NODE,                /*!< (bvsle x y) */
      BVSLT_NODE,                /*!< (bvslt x y) */
      BVSMOD_NODE,               /*!< (bvsmod x y) */
      BVSREM_NODE,               /*!< (bvsrem x y) */
      BVSUB_NODE,                /*!< (bvsub x y) */
      BVUDIV_NODE,               /*!< (bvudiv x y) */
      BVUGE_NODE,                /*!< (bvuge x y) */
      BVUGT_NODE,                /*!< (bvugt x y) */
      BVULE_NODE,                /*!< (bvule x y) */
      BVULT_NODE,                /*!< (bvult x y) */
      BVUREM_NODE,               /*!< (bvurem x y) */
      BVXNOR_NODE,               /*!< (bvxnor x y) */
      BVXOR_NODE,                /*!< (bvxor x y) */
      BV_NODE,                   /*!< (_ bvx y) */
      COMPOUND_NODE,             /*!< A compound of nodes */
      CONCAT_NODE,               /*!< (concat x y z ...) */
      DECLARE_NODE,              /*!< (declare-fun <var_name> () (_ BitVec <var_size>)) */
      DISTINCT_NODE,             /*!< (distinct x y) */
      EQUAL_NODE,                /*!< (= x y) */
      EXTRACT_NODE,              /*!< ((_ extract x y) z) */
      FORALL_NODE,               /*!< (forall ((x (_ BitVec <size>)), ...) body) */
      IFF_NODE,                  /*!< (iff x y) */
      INTEGER_NODE,              /*!< Integer node */
      ITE_NODE,                  /*!< (ite x y z) */
      LAND_NODE,                 /*!< (and x y) */
      LET_NODE,                  /*!< (let ((x y)) z) */
      LNOT_NODE,                 /*!< (and x y) */
      LOR_NODE,                  /*!< (or x y) */
      LXOR_NODE,                 /*!< (xor x y) */
      REFERENCE_NODE,            /*!< Reference node */
      STRING_NODE,               /*!< String node */
      SX_NODE,                   /*!< ((_ sign_extend x) y) */
      VARIABLE_NODE,             /*!< Variable node */
      ZX_NODE,                   /*!< ((_ zero_extend x) y) */
      ARRAY_NODE,                /*!< (Array (_ BitVec addrSize) (_ BitVec 8)) */
      SELECT_NODE,               /*!< (select array index) */
      STORE_NODE,                /*!< (store array index expr) */
    };

    //! The Representations namespace
    namespace representations {
    /*!
     *  \ingroup ast
     *  \addtogroup representations
     *  @{
     */

      //! All types of representation mode.
      enum mode_e {
        SMT_REPRESENTATION,     /*!< SMT representation */
        PYTHON_REPRESENTATION,  /*!< Python representation */
        PCODE_REPRESENTATION,   /*!< Pseudo Code representation */
        LAST_REPRESENTATION,    /*!< Must be the last item */
      };

    /*! @} End of representations namespace */
    };
  /*! @} End of ast namespace */
  };
/*! @} End of triton namespace */
};

#endif /* TRITON_ASTENUMS_HPP */
