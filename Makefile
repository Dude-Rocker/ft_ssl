# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2018/07/08 21:49:33 by vgladush          #+#    #+#              #
#    Updated: 2018/09/22 16:19:42 by vgladush         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME	=	ft_ssl
CMPL	=	gcc
FLGS	=	-Wall -Wextra -Werror
DIRF	=	./srcs/
DIRO	=	./objs/
INCL	=	./includes/ $(LIBF)/includes/
INCD	=	$(addprefix -I, $(INCL))
LIBF	=	./libft/
LBLK	=	-L $(LIBF) -lft
OBJS	=	$(FUNC:.c=.o)
OBJC	=	$(addprefix $(DIRO), $(OBJS))
FUNC	=	ft_ssl.c ft_cmd.c ft_md5.c ft_sha2.c ft_sha5.c ft_std.c ft_cipher.c\
			ft_base64.c ft_des.c ft_des_ecb.c

all: $(NAME)

$(NAME): $(OBJC)
	@make -C $(LIBF)
	@$(CMPL) -o $(NAME) $(OBJC) $(LBLK)
	@echo "\x1B[0;32m$(NAME) ready\x1B[0m"

$(DIRO)%.o: $(DIRF)%.c
	@mkdir -p $(DIRO)
	@$(CMPL) $(FLGS) $(INCD) -o $@ -c $<

clean:
	@make -C $(LIBF) clean
	@rm -rf $(DIRO)
	@echo "\x1B[1;31mobjects $(NAME) deleted\x1B[0m"

fclean:	
	# @make -C $(LIBF) fclean
	@rm -rf $(DIRO)
	@echo "\x1B[1;31mobjects $(NAME) deleted\x1B[0m"
	@rm -f $(NAME)
	@echo "\x1B[0;31m$(NAME) deleted\x1B[0m"

re: fclean all
