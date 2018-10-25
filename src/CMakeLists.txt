SET(LIB sstack)

file(GLOB SRC "*.c")
file(GLOB INC "*.h")

add_library(${LIB} ${SRC})

TARGET_LINK_LIBRARIES(${LIB} rt m dl pthread)

install (TARGETS ${LIB} DESTINATION bin)
install (FILES ${INC} DESTINATION include)
