/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putnbr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/27 13:16:52 by vgladush          #+#    #+#             */
/*   Updated: 2018/08/30 19:41:19 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_putnbr(int n)
{
	int a;

	a = n;
	if (n == -2147483648)
		write(1, "-2147483648", 11);
	else if (a < 0)
	{
		write(1, "-", 1);
		ft_putnbr(-a);
	}
	else if (a > 9)
	{
		ft_putnbr(a / 10);
		ft_putnbr(a % 10);
	}
	else
		ft_putchar(a + 48);
}
