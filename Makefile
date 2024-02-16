NAME 		= ft_traceroute
CC			= gcc
INC			= -I inc
FLAGS		= -Wall -Wextra -Werror $(INC)
LIB_PATH	= libft
BUILD_PATH	= obj
SRC_PATH	= src

SOURCES = ft_traceroute.c trace_loop.c address_ops.c send_and_replies.c sock_ops.c time_delta.c 
TEST_SOURCES = $(filter-out ft_traceroute.c,$(SOURCES)) traceroute_test.c
SRC_TEST_SOURCES = $(TEST_SOURCES:%.c=$(SRC_PATH)/%.c)


LIB_SOURCES = $(LIB_PATH)/libft.a

OBJECTS	= $(SOURCES:%.c=$(BUILD_PATH)/%.o)

.PHONY: all clean fclean re test

all: $(NAME)

$(NAME): $(OBJECTS)
	@make -s -C $(LIB_PATH)
	@$(CC) $(FLAGS_CC) -o $@ $(OBJECTS) $(LIB_SOURCES)
	@echo "** $(NAME) **"

$(BUILD_PATH)/%.o: $(SRC_PATH)/%.c
	@mkdir -p $(@D)
	@$(CC) $(FLAGS_CC) -c -o $@ $< $(INC)

test:
	@make -s -C $(LIB_PATH)
	@$(CC) $(FLAGS_CC) -o test_ft_traceroute $(SRC_TEST_SOURCES) $(LIB_SOURCES)
	@echo "Running tests"
	@./test_ft_traceroute


clean:
	@make clean -s -C $(LIB_PATH)
	@rm -rf $(BUILD_PATH)
	@echo "** clean **"

fclean: clean
	@make fclean -s -C $(LIB_PATH)
	@rm -f $(NAME) $(LIB_NAME)
	@echo "** fclean **"

re: fclean
	@make -s all
