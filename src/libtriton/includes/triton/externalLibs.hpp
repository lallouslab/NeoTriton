//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the Apache License 2.0.
*/

#pragma once

namespace triton::extlibs 
{
  //! The Capstone library namespace
  namespace capstone 
  {
    #include <capstone/arm.h>
    #include <capstone/arm64.h>
    #include <capstone/capstone.h>
    #include <capstone/x86.h>
  }
}
