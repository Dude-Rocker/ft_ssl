/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_des_ecb.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/02 22:03:18 by vgladush          #+#    #+#             */
/*   Updated: 2018/09/22 16:19:42 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

void		ft_des_ecb(t_ssl *ssl)
{
	t_des	des;
	int		i;
	int		j;

	i = 0;
	des.bt[1] = ft_strnew(0);
	while (ssl->stream[i] && i < 8)
	{
		des.bt[0] = ft_itoabase(ssl->stream[i], 2, 0);
		while (ft_strlen(des.bt[0]) < 8)
			des.bt[0] = ft_joinfree("0", des.bt[0], 2);
		des.bt[1] = ft_joinfree(des.bt[1], des.bt[0], 3);
		i++;
	}
	i = 65;
	j = 0;
	des.bt[0] = ft_strnew(LEN);
	while (i != 6)
	{
		i = (i < 6 ? LEN + i - 6 : (i == 7 ? 56 : i - 8));
		des.bt[0][j++] = des.bt[1][i];
	}
	// ssl->
}
