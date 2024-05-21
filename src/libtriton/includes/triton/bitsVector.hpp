//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#pragma once

#include <utility>

#include <triton/dllexport.hpp>
#include <triton/tritonTypes.hpp>

//! The Architecture namespace
namespace triton::arch 
{
  /*! \class BitsVector
    *  \brief This class is used to deal with registers and memory as bits vector.
    */
  class BitsVector 
  {
    protected:
      //! The highest bit of the bitvector
      triton::uint32 high;

      //! The lower bit of the bitvector
      triton::uint32 low;

    public:
      //! Constructor.
      TRITON_EXPORT BitsVector();

      //! Constructor.
      TRITON_EXPORT BitsVector(triton::uint32 high, triton::uint32 low);

      //! Constructor by copy.
      TRITON_EXPORT BitsVector(const triton::arch::BitsVector& other);

      //! Copy a BitsVector.
      TRITON_EXPORT BitsVector& operator=(const BitsVector& other);

      //! Returns the highest bit
      TRITON_EXPORT triton::uint32 getHigh(void) const;

      //! Returns the lower bit
      TRITON_EXPORT triton::uint32 getLow(void) const;

      //! Returns the size in bits of the vector
      TRITON_EXPORT triton::uint32 getVectorSize(void) const;

      //! Returns the max possible value of the bitvector.
      TRITON_EXPORT triton::uint512 getMaxValue(void) const;

      //! Sets the highest bit position
      TRITON_EXPORT void setHigh(triton::uint32 v);

      //! Sets the lower bit position
      TRITON_EXPORT void setLow(triton::uint32 v);

      //! Sets the bits (high, low) position
      TRITON_EXPORT void setBits(triton::uint32 high, triton::uint32 low);
  };

  //! Displays a BitsVector.
  TRITON_EXPORT std::ostream& operator<<(std::ostream& stream, const BitsVector& bv);

  //! Displays a BitsVector.
  TRITON_EXPORT std::ostream& operator<<(std::ostream& stream, const BitsVector* bv);
};
